/*-
 * Copyright (c) 2023 Bojan Novković <bnovkov@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/event.h>
#include <sys/hwt.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <sys/smp.h>
#include <sys/errno.h>
#include <sys/taskqueue.h>
#include <sys/domainset.h>
#include <sys/sleepqueue.h>

#include <vm/vm.h>
#include <vm/vm_page.h>

#include <machine/cpufunc.h>
#include <machine/param.h>
#include <machine/atomic.h>
#include <machine/smp.h>
#include <machine/specialreg.h>

#include <x86/apicvar.h>
#include <x86/x86_var.h>

#include <dev/hwt/hwt_vm.h>
#include <dev/hwt/hwt_thread.h>
#include <dev/hwt/hwt_cpu.h>
#include <dev/hwt/hwt_config.h>
#include <dev/hwt/hwt_context.h>
#include <dev/hwt/hwt_backend.h>
#include <dev/hwt/hwt_hook.h>
#include <dev/hwt/hwt_intr.h>

#include "pt.h"

#ifdef PT_DEBUG
#define dprintf(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define dprintf(fmt, ...)
#endif

#define PT_XSAVE_MASK (XFEATURE_ENABLED_X87 | XFEATURE_ENABLED_SSE)

MALLOC_DEFINE(M_PT, "pt", "Intel Processor Trace");

SDT_PROVIDER_DECLARE(pt);
SDT_PROBE_DEFINE(pt, , , topa__intr);

extern struct taskqueue *taskqueue_hwt;

static bool loaded = false;

struct pt_save_area {
	uint8_t legacy_state[512];
	struct xsave_header header;
	struct pt_ext_area pt_ext_area;
} __aligned(64);

struct pt_buffer {
	uint64_t *topa_hw;  /* ToPA table entries. */
	struct mtx pmi_mtx; /* spinlock for pt_backend_read */
	bool ready;
	vm_offset_t offset;
	int curpage;
};

struct pt_ctx {
	struct pt_buffer buf;  /* ToPA buffer metadata */
	struct task task;      /* ToPA buffer kevent task */
	struct thread *hwt_td; /* hwt(8) tracing thread */
	int kqueue_fd;
	struct pt_save_area save_area; /* PT XSAVE area */
};

/* XXX: WIP */
struct pt_thread {
	struct pt_ctx ctx;
};

static struct pt_cpu {
	struct hwt_thread *hwt_td; /* hwt thread active on cpu */
	struct pt_ctx ctx;	   /* save area for CPU mode */
	volatile int terminating;  /* used as part of trace stop protocol */
} *pt_pcpu;

/*
 * PT-related CPUID bits.
 */
static struct pt_cpu_info {
	uint32_t l0_eax;
	uint32_t l0_ebx;
	uint32_t l0_ecx;
	uint32_t l1_eax;
	uint32_t l1_ebx;
} pt_info;

static int pt_topa_intr(struct trapframe *tf);

static __inline void
xrstors(char *addr, uint64_t mask)
{
	uint32_t low, hi;

	low = mask;
	hi = mask >> 32;
	__asm __volatile("xrstors %0" : : "m"(*addr), "a"(low), "d"(hi));
}

static __inline void
xsaves(char *addr, uint64_t mask)
{
	uint32_t low, hi;

	low = mask;
	hi = mask >> 32;
	__asm __volatile("xsaves %0"
			 : "=m"(*addr)
			 : "a"(low), "d"(hi)
			 : "memory");
}

/*
 * Enables or disables tracing on curcpu.
 */
static void
pt_cpu_toggle_local(struct pt_save_area *save_area, bool enable)
{
	u_long xcr0, cr0;
	u_long xss;

	KASSERT((curthread)->td_critnest >= 1,
	    ("%s: not in critical section", __func__));

	cr0 = rcr0();
	if (cr0 & CR0_TS)
		clts();
	xcr0 = rxcr(XCR0);
	if ((xcr0 & PT_XSAVE_MASK) != PT_XSAVE_MASK)
		load_xcr(XCR0, xcr0 | PT_XSAVE_MASK);
	xss = rdmsr(MSR_IA32_XSS);
	wrmsr(MSR_IA32_XSS, xss | XFEATURE_ENABLED_PT);

	if (!enable) {
		KASSERT((rdmsr(MSR_IA32_RTIT_CTL) & RTIT_CTL_TRACEEN) != 0,
		    ("%s: PT is disabled", __func__));
		xsaves((char *)save_area, XFEATURE_ENABLED_PT);
	} else {
		KASSERT((rdmsr(MSR_IA32_RTIT_CTL) & RTIT_CTL_TRACEEN) == 0,
		    ("%s: PT is enabled", __func__));
		xrstors((char *)save_area, XFEATURE_ENABLED_PT);
	}
	wrmsr(MSR_IA32_XSS, xss);
	if ((xcr0 & PT_XSAVE_MASK) != PT_XSAVE_MASK)
		load_xcr(XCR0, xcr0);
	if (cr0 & CR0_TS)
		load_cr0(cr0);
}

/*
 * Dumps contents of PT-related registers.
 */
static void
pt_cpu_dump(int cpu_id)
{
#ifdef PT_DEBUG
	struct pt_save_area *area = &pt_pcpu[cpu_id].ctx.save_area;

	printf("dumping PT info for cpu %d\n", cpu_id);

	printf("rtit_ctl: 0x%zx\n", area->pt_ext_area.rtit_ctl);
	printf("rtit_addr0_a: 0x%zx\n", area->pt_ext_area.rtit_addr0_a);
	printf("rtit_addr0_b: 0x%zx\n", area->pt_ext_area.rtit_addr0_b);

	printf("xsave_bv: 0x%zx\n", area->header.xsave_bv);
	printf("xcomp_bv: 0x%zx\n", area->header.xcomp_bv);

	printf("rtit_status MSR: 0x%zx\n", rdmsr(MSR_IA32_RTIT_STATUS));
	printf("rtit_ctl MSR: 0x%zx\n", rdmsr(MSR_IA32_RTIT_CTL));
	printf("rtit output base MSR: 0x%zx\n",
	    rdmsr(MSR_IA32_RTIT_OUTPUT_BASE));
	printf("rtit mask_ptrs MSR: 0x%zx\n",
	    rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS));
	printf("rtit_addr0_a MSR: 0x%zx\n", rdmsr(MSR_IA32_RTIT_ADDR0_A));

	lapic_dump("0");
#endif
}

/*
 * CPU mode helper routines.
 */
static void
pt_cpu_init(void *dummy)
{
	struct pt_cpu *cpu = &pt_pcpu[curcpu];
	dprintf("%s: curcpu %d\n", __func__, curcpu);
	/* Enable XSAVE. */
	load_cr4(rcr4() | CR4_XSAVE);
	/* Clear PMI status. */
	wrmsr(MSR_IA32_RTIT_STATUS, 0);
	/* Start tracing. */
	pt_cpu_toggle_local(&cpu->ctx.save_area, true);
	pt_cpu_dump(curcpu);
}

static void
pt_cpu_stop(void *dummy)
{
	struct pt_cpu *cpu = &pt_pcpu[curcpu];
	dprintf("%s: curcpu %d\n", __func__, curcpu);
	/* Check if the CPU was initialized */
	if (cpu->ctx.buf.topa_hw == NULL)
		return;
	/* Stop tracing. */
	pt_cpu_toggle_local(&cpu->ctx.save_area, false);
}

/*
 * Disables ToPA PMI on curcpu.
 * Used as an smp_rendevous action function.
 */
static void
pt_cpu_mask_pcint(void *dummy __unused)
{
	pt_cpu_dump(curcpu);
	lapic_disable_pt_pmi();
}

static int
pt_topa_prepare(struct pt_ctx *ctx, struct hwt_vm *vm)
{
	int i;
	struct pt_buffer *buf = &ctx->buf;
	size_t topa_size = TOPA_SIZE_4K; /* 4K only for now */

	KASSERT(buf->topa_hw == NULL,
	    ("%s: ToPA info already exists", __func__));
	/* Allocate array of TOPA entries. */
	buf->topa_hw = malloc((vm->npages + 1) * sizeof(uint64_t), M_PT,
	    M_WAITOK | M_ZERO);
	dprintf("%s: ToPA virt addr %p\n", __func__, buf->topa_hw);
	for (i = 0; i < vm->npages; i++) {
		buf->topa_hw[i] = VM_PAGE_TO_PHYS(vm->pages[i]) | topa_size;
		/*
		 * XXX: TOPA_INT should ideally be set according to
		 * expected amount of incoming trace data. Too few TOPA_INT
		 * entries will not trigger interrupts often enough when tracing
		 * smaller functions.
		 */
		/* Raise interrupt when entry is filled. */
		buf->topa_hw[i] |= TOPA_INT;
	}
	/* Circular buffer - point last entry to first */
	buf->topa_hw[vm->npages] = (uint64_t)vtophys(buf->topa_hw) | TOPA_END;

	return (0);
}

static int
pt_backend_init_thread(struct hwt_context *ctx)
{
	struct hwt_thread *thr;

	HWT_CTX_LOCK(ctx);
	TAILQ_FOREACH (thr, &ctx->threads, next) {
		KASSERT(thr->cookie == NULL,
		    ("%s: thr->cookie not NULL - %p", __func__, thr->cookie));
		thr->cookie = malloc(sizeof(struct pt_thread), M_PT,
		    M_ZERO | M_WAITOK);
	}
	HWT_CTX_UNLOCK(ctx);

	return (ENXIO);
}

static int
pt_configure_ranges(struct pt_ctx *ctx, struct pt_cpu_config *cfg)
{
	struct pt_ext_area *pt_ext;
	struct pt_save_area *save_area;
	int nranges_supp, n, error = 0;

	save_area = &ctx->save_area;
	pt_ext = &save_area->pt_ext_area;

	if (pt_info.l0_ebx & CPUPT_IPF) {
		/* How many IP ranges does the CPU support? */
		nranges_supp = (pt_info.l1_eax & CPUPT_NADDR_M) >>
		    CPUPT_NADDR_S;

		/* xsave/xrstor supports two ranges only. */
		if (nranges_supp > 2)
			nranges_supp = 2;
		n = cfg->nranges;
		if (n > nranges_supp) {
			printf(
			    "%s: %d IP filtering ranges requested, CPU supports %d, truncating\n",
			    __func__, n, nranges_supp);
			n = nranges_supp;
		}

		switch (n) {
		case 2:
			pt_ext->rtit_ctl |= (1UL << RTIT_CTL_ADDR_CFG_S(1));
			pt_ext->rtit_addr1_a = cfg->ip_ranges[1].start;
			pt_ext->rtit_addr1_b = cfg->ip_ranges[1].end;
		case 1:
			pt_ext->rtit_ctl |= (1UL << RTIT_CTL_ADDR_CFG_S(0));
			pt_ext->rtit_addr0_a = cfg->ip_ranges[0].start;
			pt_ext->rtit_addr0_b = cfg->ip_ranges[0].end;
			break;
		default:
			error = (EINVAL);
			break;
		};
	} else {
		error = (ENXIO);
	}

	return error;
}

// TODO: decouple configuration logic from CPU mode
static int
pt_backend_configure(struct hwt_context *ctx, int cpu_id, int session_id)
{
	struct pt_ctx *pt_ctx;
	struct hwt_cpu *hwt_cpu;
	struct pt_ext_area *pt_ext;
	struct xsave_header *hdr;
	struct pt_cpu_config *cfg = (struct pt_cpu_config *)ctx->config;
	int error = 0;

	dprintf("%s\n", __func__);

	/* Sanitize input. */
	// cfg->rtit_ctl &= PT_SUPPORTED_FLAGS;
	/* Validate user configuration */
	if (cfg->rtit_ctl & RTIT_CTL_MTCEN) {
		if ((pt_info.l0_ebx & CPUPT_MTC) == 0) {
			printf(
			    "%s: CPU does not support generating MTC packets\n",
			    __func__);
			return (ENXIO);
		}
	}

	if (cfg->rtit_ctl & RTIT_CTL_CR3FILTER) {
		if ((pt_info.l0_ebx & CPUPT_CR3) == 0) {
			printf("%s: CPU does not support CR3 filtering\n",
			    __func__);
			return (ENXIO);
		}
	}

	if (cfg->rtit_ctl & RTIT_CTL_DIS_TNT) {
		if ((pt_info.l0_ebx & CPUPT_DIS_TNT) == 0) {
			printf("%s: CPU does not support TNT\n", __func__);
			return (ENXIO);
		}
	}
	/* TODO: support for more config bits */

	TAILQ_FOREACH (hwt_cpu, &ctx->cpus, next) {
		if (hwt_cpu->cpu_id != cpu_id)
			continue;

		dprintf("%s: cpuid %d\n", __func__, cpu_id);
		pt_ctx = &pt_pcpu[cpu_id].ctx;
		pt_ext = &pt_ctx->save_area.pt_ext_area;
		hdr = &pt_ctx->save_area.header;

		KASSERT(pt_ctx->buf.topa_hw == NULL,
		    ("%s: active ToPA buffer in cpu %d\n", __func__,
			hwt_cpu->cpu_id));
		memset(&pt_pcpu[hwt_cpu->cpu_id], 0, sizeof(struct pt_cpu));

		dprintf("%s: preparing IPF ranges\n", __func__);
		pt_ext->rtit_ctl |= cfg->rtit_ctl;
		if ((error = pt_configure_ranges(pt_ctx, cfg)) != 0) {
			return error;
		}

		dprintf("%s: preparing ToPA buffer\n", __func__);
		if (pt_topa_prepare(pt_ctx, hwt_cpu->vm) != 0) {
			dprintf("%s: failed to prepare ToPA buffer\n",
			    __func__);
			return (-1);
		}

		dprintf("%s: preparing MSRs\n", __func__);
		/* Save hwt_td for kevent */
		pt_ctx->hwt_td = ctx->hwt_td;
		pt_ctx->kqueue_fd = ctx->kqueue_fd;
		/* Prepare ToPA MSR values. */
		pt_ext->rtit_ctl |= RTIT_CTL_TOPA;
		pt_ext->rtit_output_base = (uint64_t)vtophys(
		    pt_ctx->buf.topa_hw);
		pt_ext->rtit_output_mask_ptrs = 0x7f;
		/* Init header */
		hdr->xsave_bv = XFEATURE_ENABLED_PT;
		hdr->xcomp_bv = XFEATURE_ENABLED_PT |
		    (1ULL << 63) /* compaction */;
		/* Enable tracing. */
		pt_ext->rtit_ctl |= RTIT_CTL_TRACEEN;
	}
	return (0);
}

/*
 * hwt backend trace start operation. CPU affine.
 */
static void
pt_backend_enable(struct hwt_context *ctx, int cpu_id)
{
	KASSERT(curcpu == cpu_id,
	    ("%s: attempting to start PT on another cpu", __func__));
	pt_cpu_init(NULL);
}

/*
 * hwt backend trace stop operation. CPU affine.
 */
static void
pt_backend_disable(struct hwt_context *ctx, int cpu_id)
{
	KASSERT(curcpu == cpu_id,
	    ("%s: attempting to disable PT on another cpu", __func__));
	pt_cpu_stop(NULL);
}

/*
 * hwt backend trace start operation for remote CPUs.
 */
static void
pt_backend_enable_smp(struct hwt_context *ctx)
{
	dprintf("%s\n", __func__);
	smp_rendezvous_cpus(ctx->cpu_map, NULL, pt_cpu_init, NULL, NULL);
}

/*
 * hwt backend trace stop operation for remote CPUs.
 */
static void
pt_backend_disable_smp(struct hwt_context *ctx)
{
	int cpu_id;
	struct pt_cpu *cpu;

	dprintf("%s\n", __func__);
	/* Signal trace stop to active interrupt handlers. */
	CPU_FOREACH (cpu_id) {
		if (!CPU_ISSET(cpu_id, &ctx->cpu_map))
			continue;
		cpu = &pt_pcpu[cpu_id];
		atomic_store_int(&cpu->terminating, 1);
	}
	/* Mask ToPA PMI on active CPUs. */
	smp_rendezvous_cpus(ctx->cpu_map, NULL, pt_cpu_mask_pcint, NULL, NULL);
	/* Wait for each CPU to exit ISR. */
	pause((void *)pt_backend_disable_smp, hz / 4);
	/* Deactivate PT. */
	smp_rendezvous_cpus(ctx->cpu_map, NULL, pt_cpu_stop, NULL, NULL);
}

static int
pt_backend_init(struct hwt_context *ctx)
{
	int error = 0;

	dprintf("%s\n", __func__);
	if (ctx->mode == HWT_MODE_THREAD)
		error = pt_backend_init_thread(ctx);
	if (error != 0)
		return (error);

	/* Configure PMI on all CPUs. */
	if (lapic_enable_pmc() == 0) {
		printf("%s: unable to enable pcint interrupts\n", __func__);
		return (-1);
	}
	/* Install ToPA PMI handler. */
	KASSERT(hwt_intr == NULL,
	    ("%s: ToPA PMI handler already present", __func__));
	hwt_intr = pt_topa_intr;
	wmb();

	return (error);
}

static void
pt_backend_deinit(struct hwt_context *ctx)
{
	/* struct hwt_thread *thr; */
	struct pt_cpu *cpu;

	dprintf("%s\n", __func__);

	/* Remove ToPA PMI handler. */
	hwt_intr = NULL;
	wmb();

	/* Stop tracing on all active CPUs */
	pt_backend_disable_smp(ctx);
	lapic_disable_pmc();
	if (ctx->mode == HWT_MODE_THREAD) {
		/* HWT_CTX_LOCK(ctx); */
		/* TAILQ_FOREACH (thr, &ctx->threads, next) { */
		/* 	KASSERT(thr->cookie != NULL, */
		/* 	    ("%s: thr->cookie not set", __func__)); */
		/* 	free(thr->cookie, M_PT); */
		/* 	thr->cookie = NULL; */
		/* } */
		/* HWT_CTX_UNLOCK(ctx); */
	} else {
		CPU_FOREACH (cpu_id) {
			if (!CPU_ISSET(cpu_id, &ctx->cpu_map))
				continue;
			cpu = &pt_pcpu[cpu_id];
			/* Free ToPA table. */
			free(cpu->ctx.buf.topa_hw, M_PT);
			cpu->ctx.buf.topa_hw = NULL;
		}
	}
}

/*
 * Fetches new offset into the tracing buffer, if any.
 * Blocks until notified by the PMI interrupt handler.
 */
static int
pt_backend_read(int cpu_id, int *curpage, vm_offset_t *curpage_offset)
{
	int error = 0;
	struct pt_buffer *buf = &pt_pcpu[cpu_id].ctx.buf;

	dprintf("%s\n", __func__);
	if (buf->topa_hw == NULL)
		return (-1);

	mtx_lock_spin(&buf->pmi_mtx);
	if (!buf->ready) {
		if (msleep_spin(buf, &buf->pmi_mtx, "ptread", 0) ==
		    EWOULDBLOCK) {
			error = ENOENT;
			goto out;
		}
		if (!buf->ready) {
			error = ENOENT;
			goto out;
		}
	}
	*curpage = buf->curpage;
	*curpage_offset = buf->offset;
	buf->ready = false;
	wmb();
out:
	mtx_unlock_spin(&buf->pmi_mtx);

	return (error);
}

static void
pt_backend_dump(int cpu_id)
{
	return;
}

static struct hwt_backend_ops pt_ops = {
	.hwt_backend_init = pt_backend_init,
	.hwt_backend_deinit = pt_backend_deinit,

	.hwt_backend_configure = pt_backend_configure,

	.hwt_backend_enable = pt_backend_enable,
	.hwt_backend_disable = pt_backend_disable,

#ifdef SMP
	.hwt_backend_enable_smp = pt_backend_enable_smp,
	.hwt_backend_disable_smp = pt_backend_disable_smp,
#endif

	.hwt_backend_read = pt_backend_read,
	.hwt_backend_dump = pt_backend_dump,
};
static struct hwt_backend backend = {
	.ops = &pt_ops,
	.name = "pt",
};

/*
 * ToPA PMI kevent task.
 */
static void
pt_buffer_ready(void *arg, int pending __unused)
{
	struct pt_ctx *ctx = arg;
	struct kevent kev;
	int ret __diagused;
	int64_t data = (ctx->buf.curpage * PAGE_SIZE) + ctx->buf.offset;

	dprintf("%s: cpu %d, kqueue_fd %d, data 0x%zx, td %p\n", __func__,
	    curcpu, ctx->kqueue_fd, data, ctx->hwt_td);
	EV_SET(&kev, HWT_PT_BUF_RDY_EV, EVFILT_USER, 0, NOTE_TRIGGER, data,
	    NULL);
	ret = kqfd_register(ctx->kqueue_fd, &kev, ctx->hwt_td, M_WAITOK);
	dprintf("%s: kqfd ret %d\n", __func__, ret);
	KASSERT(ret == 0,
	    ("%s: kqueue fd register failed: %d\n", __func__, ret));
}

/*
 * ToPA PMI handler.
 */
static int
pt_topa_intr(struct trapframe *tf)
{
	int retval = 0;
	uint64_t reg;
	struct pt_ctx *ctx;
	struct pt_buffer *buf;

	SDT_PROBE0(pt, , , topa__intr);
	/* TODO: handle possible double entry */
	/* Check ToPA PMI status on curcpu. */
	reg = rdmsr(MSR_IA_GLOBAL_STATUS);
	if ((reg & GLOBAL_STATUS_FLAG_TRACETOPAPMI) == 0)
		return (retval);

	/* Disable preemption. */
	critical_enter();
	retval = 1;
	/* Only CPU mode supported for now */
	ctx = &pt_pcpu[curcpu].ctx;
	buf = &ctx->buf;
	KASSERT(buf->topa_hw != NULL,
	    ("%s: ToPA PMI interrupt with invalid buffer", __func__));

	/* Disable tracing so we don't trace the PMI handler. */
	pt_cpu_toggle_local(&ctx->save_area, false);
	/* Update buffer offset. */
	reg = rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS);

	mtx_lock_spin(&buf->pmi_mtx);
	buf->curpage = (reg & 0xffffff80) >> 7;
	buf->offset = reg >> 32;
	buf->ready = true;
	wmb();
	mtx_unlock_spin(&buf->pmi_mtx);

	/* Notify pt_backend_read. */
	wakeup(buf);
	dprintf("%s: woke up pt_backend_read\n", __func__);

	/* XXX: kevents registered this way never make it to userspace. */
	/* TASK_INIT(&ctx->task, 0, (task_fn_t *)pt_buffer_ready, ctx); */
	/* taskqueue_enqueue(taskqueue_hwt, &ctx->task); */

	/* Clear ToPA PMI status. */
	reg = rdmsr(MSR_IA_GLOBAL_STATUS_RESET);
	reg &= ~GLOBAL_STATUS_FLAG_TRACETOPAPMI;
	reg |= GLOBAL_STATUS_FLAG_TRACETOPAPMI;
	wrmsr(MSR_IA_GLOBAL_STATUS_RESET, reg);

	/* Don't re-enable ToPA PMI if trace stop was requested. */
	if (atomic_load_acq_int(&pt_pcpu[curcpu].terminating) == 0)
		lapic_reenable_pmc();
	/* Re-enable tracing. */
	pt_cpu_toggle_local(&ctx->save_area, true);
	/* Enable preemption. */
	critical_exit();

	return (retval);
}

static int
pt_init(void)
{
	u_int cp[4];

	dprintf("Enumerating part 1\n");

	cpuid_count(PT_CPUID, 0, cp);
	dprintf("%s: Maximum valid sub-leaf Index: %x\n", __func__, cp[0]);
	dprintf("%s: ebx %x\n", __func__, cp[1]);
	dprintf("%s: ecx %x\n", __func__, cp[2]);

	/* Save relevant cpuid info. */
	pt_info.l0_eax = cp[0];
	pt_info.l0_ebx = cp[1];
	pt_info.l0_ecx = cp[2];

	dprintf("Enumerating part 2\n");

	cpuid_count(PT_CPUID, 1, cp);
	dprintf("%s: eax %x\n", __func__, cp[0]);
	dprintf("%s: ebx %x\n", __func__, cp[1]);

	pt_info.l1_eax = cp[0];
	pt_info.l1_ebx = cp[1];

	return (0);
}

static bool
pt_supported(void)
{
	u_int cp[4];

	/* Intel SDM Vol. 3C, 33-30 */
	if ((cpu_stdext_feature & CPUID_STDEXT_PROCTRACE) == 0) {
		printf("pt: CPU does not support Intel Processor Trace\n");
		return (false);
	}

	/* Require XSAVE support. */
	if ((cpu_feature2 & CPUID2_XSAVE) == 0) {
		printf("pt: XSAVE is not supported\n");
		return (false);
	}

	cpuid_count(0xd, 0x0, cp);
	if ((cp[0] & PT_XSAVE_MASK) != PT_XSAVE_MASK) {
		printf("pt: CPU does not support X87 or SSE: %x", cp[0]);
		return (false);
	}

	cpuid_count(0xd, 0x1, cp);
	if ((cp[0] & (1 << 0)) == 0) {
		printf("pt: XSAVE compaction is not supported\n");
		return (false);
	}
	if ((cp[0] & (1 << 3)) == 0) {
		printf("pt: XSAVES/XRSTORS are not supported\n");
		return (false);
	}

	/* Require ToPA support. */
	cpuid_count(PT_CPUID, 0, cp);
	if ((cp[2] & CPUPT_TOPA) == 0) {
		printf("pt: ToPA is not supported\n");
		return (false);
	}
	if ((cp[2] & CPUPT_TOPA_MULTI) == 0) {
		printf("pt: multiple ToPA outputs are not supported\n");
		return (false);
	}

	return (true);
}

static int
pt_modevent(module_t mod, int type, void *data)
{
	int error;

	switch (type) {
	case MOD_LOAD:
		if (!pt_supported()) {
			return (ENXIO);
		}
		pt_init();
		error = hwt_backend_register(&backend);
		if (error != 0) {
			printf("pt: unable to register hwt backend, error %d\n",
			    error);
			return (error);
		}
		pt_pcpu = malloc(sizeof(struct pt_cpu) * mp_ncpus, M_PT,
		    M_ZERO | M_WAITOK);
		for (int i = 0; i < mp_ncpus; i++)
			mtx_init(&pt_pcpu[i].ctx.buf.pmi_mtx, "ToPA PMI", NULL,
			    MTX_SPIN);
		loaded = true;
		break;
	case MOD_UNLOAD:
		if (loaded) {
			hwt_backend_unregister(&backend);
			hwt_intr = NULL;
			free(pt_pcpu, M_PT);
			pt_pcpu = NULL;
		}
		break;
	default:
		break;
	}

	return (0);
}

static moduledata_t pt_mod = { "intel_pt", pt_modevent, NULL };

DECLARE_MODULE(intel_pt, pt_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_DEPEND(intel_pt, hwt, 1, 1, 1);
MODULE_VERSION(intel_pt, 1);
