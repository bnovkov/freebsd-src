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
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/rman.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/smp.h>
#include <sys/hwt.h>
#include <sys/bus.h>
#include <sys/taskqueue.h>
#include <sys/event.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sdt.h>


#include <x86/include/x86_var.h>
#include <x86/include/intr_machdep.h>
#include <x86/include/apicvar.h>
#include <x86/include/specialreg.h>
#include <machine/cpufunc.h>

#include <vm/vm.h>
#include <vm/vm_page.h>

#include <dev/hwt/hwt_context.h>
#include <dev/hwt/hwt_config.h>
#include <dev/hwt/hwt_cpu.h>
#include <dev/hwt/hwt_thread.h>
#include <dev/hwt/hwt_backend.h>
#include <dev/hwt/hwt_vm.h>
#include <dev/hwt/hwt_hook.h>
#include <dev/hwt/hwt_intr.h>

#include "pt.h"

#ifdef  PT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#define	PT_XSAVE_MASK	(XFEATURE_ENABLED_X87 | XFEATURE_ENABLED_SSE)

MALLOC_DEFINE(M_PT, "pt", "Intel Processor Trace");

SDT_PROVIDER_DECLARE(pt);
SDT_PROBE_DEFINE(pt, , , topa__intr);

/* IPI handler */
extern inthand_t IDTVEC(pt_toggle_isr);

static struct mtx pt_mtx;
static struct hwt_backend_ops pt_ops;
bool loaded = false;

/* TODO: will be useful for multiple ToPA size support. */
/* struct topa_entry { */
/* 	uint64_t base; */
/* 	uint64_t size; */
/* 	uint64_t offset; */
/* }; */

struct pt_save_area {
	uint8_t			legacy_state[512];
	struct xsave_header	header;
	struct pt_ext_area	pt_ext_area;
} __aligned(64);

struct pt_buffer{
  uint64_t		*topa_hw; /* ToPA table entries. */
  int curpage;
  vm_offset_t offset;
};

static struct pt_cpu {
  struct pt_save_area save_area;
  struct hwt_vm *vm;
  struct thread *hwt_td;
  struct pt_buffer buf;
  struct task	task;
  uint32_t  lvt_pm_msr;
} pt_pcpu[MAXCPU];

struct pt_cpu_info {
  uint32_t			l0_eax;
	uint32_t			l0_ebx;
	uint32_t			l0_ecx;
	uint32_t			l1_eax;
	uint32_t			l1_ebx;
} pt_info;


static int pt_ipinum = -1;

static int kqueue_fd;
static struct hwt_backend backend = {
  .ops = &pt_ops,
  .name = "pt",
};

extern struct taskqueue *taskqueue_hwt;

static __inline void
xrstors(char *addr, uint64_t mask)
{
	uint32_t low, hi;

	low = mask;
	hi = mask >> 32;
	__asm __volatile("xrstors %0" : : "m" (*addr), "a" (low), "d" (hi));
}

static __inline void
xsaves(char *addr, uint64_t mask)
{
	uint32_t low, hi;

	low = mask;
	hi = mask >> 32;
	__asm __volatile("xsaves %0" : "=m" (*addr) : "a" (low), "d" (hi) :
                   "memory");
}

static void
pt_save_restore(struct pt_cpu *pt_pc, bool save)
{
	u_long xcr0, cr0;
	u_long xss;
  uint32_t lvt_pcint_msr;

  KASSERT((curthread)->td_critnest >= 1, ("Not in critical section"));
	cr0 = rcr0();
	if (cr0 & CR0_TS)
		clts();
	xcr0 = rxcr(XCR0);
	if ((xcr0 & PT_XSAVE_MASK) != PT_XSAVE_MASK)
		load_xcr(XCR0, xcr0 | PT_XSAVE_MASK);
	xss = rdmsr(MSR_IA32_XSS);
	wrmsr(MSR_IA32_XSS, xss | XFEATURE_ENABLED_PT);
	if (save) {
		KASSERT((rdmsr(MSR_IA32_RTIT_CTL) & RTIT_CTL_TRACEEN) != 0,
            ("%s: PT is disabled", __func__));
		xsaves((char *)&pt_pc->save_area, XFEATURE_ENABLED_PT);
    /* Clear PCINT MSR. */
    lvt_pcint_msr = rdmsr32();
    lvt_pcint_msr |= APIC_LVT_PCINT_MASK_BIT;
    lvt_pcint_msr &= ~APIC_LVT_PCINT_DELIVERY_MASK;
    wrmsr(MSR_APIC_LVT_PCINT, lvt_pcint_msr);
	} else {
		KASSERT((rdmsr(MSR_IA32_RTIT_CTL) & RTIT_CTL_TRACEEN) == 0,
            ("%s: PT is enabled", __func__));
    /* Set PCINT MSR. */
    lvt_pcint_msr = rdmsr32();
    lvt_pcint_msr &= ~(APIC_LVT_PCINT_MASK_BIT | APIC_LVT_PCINT_DELIVERY_MASK);
    /* Deliver ToPA interrupt using NMI */
    lvt_pcint_msr |= APIC_LVT_PCINT_DELIVERY_NMI;
    wrmsr(MSR_APIC_LVT_PCINT, lvt_pcint_msr);
		xrstors((char *)&pt_pc->save_area, XFEATURE_ENABLED_PT);
	}
	wrmsr(MSR_IA32_XSS, xss);
	if ((xcr0 & PT_XSAVE_MASK) != PT_XSAVE_MASK)
		load_xcr(XCR0, xcr0);
	if (cr0 & CR0_TS)
		load_cr0(cr0);
}

static void
pt_cpu_start(struct pt_cpu *cpu){
  dprintf("%s\n", __func__);
  pt_save_restore(cpu, false);
}

static void
pt_cpu_stop(struct pt_cpu *cpu){
  dprintf("%s\n", __func__);
  pt_save_restore(cpu, true);
}

static int
pt_topa_prepare(struct pt_cpu *cpu){
  int i;
  struct hwt_vm *vm = cpu->vm;
  struct pt_buffer *buf = &cpu->buf;
  size_t topa_size = TOPA_SIZE_4K; /* 4K only for now */

  KASSERT(buf->topa_hw == NULL, ("%s: ToPA info already exists", __func__));
  /* Allocate array of TOPA entries. */
  buf->topa_hw = malloc((vm->npages + 1) * sizeof(uint64_t), M_PT, M_WAITOK | M_ZERO);
  for(i = 0; i < vm->npages; i++){
    buf->topa_hw[i] = VM_PAGE_TO_PHYS(vm->pages[i]) | topa_size;
    if(i == vm->npages/2 || i + 1 == vm->npages){
      /* Raise interrupt when entry is filled. */
      buf->topa_hw[i] |= TOPA_INT;
    }
  }
  /* Circular buffer - point last entry to first */
  buf->topa_hw[vm->npages] = buf->topa_hw[0] | TOPA_END;

  return (0);
}

/*
 * Starts tracing on target CPU by sending an IPI.
 */
static int
pt_init_cpu(int cpu_id){
  ipi_cpu(cpu_id, pt_ipinum);

	return (0);
}

static int
pt_backend_init_thread(struct hwt_context *ctx)
{
  /* TODO: thread mode will require a per-thread PT xsave block */
  // hwt_hook = pt_hwt_hook;
	return (-1);
}

static int
pt_backend_init_cpu(struct hwt_context *ctx)
{
  struct hwt_cpu *cpu;

  TAILQ_FOREACH(cpu, &ctx->cpus, next) {
    if(pt_init_cpu(cpu, ctx->hwt_td)){
      return (-1);
    }
  }
	return (0);
}

static int
pt_backend_init(struct hwt_context *ctx)
{
	int error = 0;

  dprintf("%s\n", __func__);
	if (ctx->mode == HWT_MODE_THREAD)
		error = pt_backend_init_thread(ctx);
	else
		error = pt_backend_init_cpu(ctx);

  if(error != 0)
    return (error);

  dprintf("%s: kqueue fd: %d\n", __func__, ctx->kqueue_fd);
  kqueue_fd = ctx->kqueue_fd;

  /* Install ToPA PMI handler. */
  KASSERT(hwt_intr == NULL, ("%s: ToPA PMI handler already present", __func__));
  hwt_intr = pt_topa_intr;

	return (error);
}

static void
pt_backend_deinit(struct hwt_context *ctx)
{
  struct hwt_cpu *cpu;
  struct pt_cpu *pt_cpu;
  struct pt_buffer *buf;

  dprintf("%s\n", __func__);
  /* Remove ToPA PMI handler. */
  KASSERT(hwt_intr != NULL, ("%s: ToPA PMI handler not present", __func__));
  hwt_intr = NULL;

  TAILQ_FOREACH(cpu, &ctx->cpus, next) {
    pt_cpu = &pt_pcpu[cpu->cpu_id];
    buf = &pt_cpu->buf;

    if(pt_cpu->vm == cpu->vm && buf->topa_hw != NULL){
      free(buf->topa_hw, M_PT);
      buf->topa_hw = NULL;
      pt_cpu->vm = NULL;
      /* Stop tracing - HWT_IOC_STOP is not implemented yet */
      pt_cpu_stop(pt_cpu);
    }
  }
}

static int
pt_configure_ranges(struct pt_cpu *pt_cpu, struct pt_cpu_config *cfg)
{
	struct pt_ext_area *pt_ext;
	struct pt_save_area *save_area;
	int nranges_supp, n, error = 0;

	save_area = &pt_cpu->save_area;
	pt_ext = &save_area->pt_ext_area;

	if (pt_info.l0_ebx & CPUPT_IPF) {
		/* How many ranges CPU does support ? */
		nranges_supp = (pt_info.l1_eax & CPUPT_NADDR_M) >> CPUPT_NADDR_S;

		/* xsave/xrstor supports two ranges only */
		if (nranges_supp > 2)
			nranges_supp = 2;
    n = cfg->nranges;
    if(n > nranges_supp){
      printf("%s: %d IP filtering ranges requested, CPU supports %d, truncating\n", __func__, n, nranges_supp);
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
		default:
      error = (EINVAL);
			break;
		};
	} else {
    error = (ENXIO);
  }

  return error;
}

static int
pt_backend_configure(struct hwt_context *ctx, int cpu_id, int session_id)
{
  struct pt_cpu *pt_cpu = &pt_pcpu[cpu_id];
  struct pt_ext_area *pt_ext;
  struct xsave_header *hdr;
  struct pt_cpu_config *cfg = (struct pt_cpu_config *)ctx->config;
  int error = 0;

  dprintf("%s\n", __func__);

  KASSERT(pt_cpu->vm == NULL, ("%s: active hwt_vm context in cpu %d\n", __func__, cpu->cpu_id));
  KASSERT(pt_cpu->buf.topa_hw == NULL, ("%s: active ToPA buffer in cpu %d\n", __func__, cpu->cpu_id));

  pt_ext = &pt_cpu->save_area.pt_ext_area;
  hdr = &pt_cpu->save_area.header;

  /* TODO: sanitize input with 'supported' mask. */
	if (cfg->rtit_ctl & RTIT_CTL_MTCEN){
    if((pt_info.l0_ebx & CPUPT_MTC) == 0 ){
      printf("%s: CPU does not support generating MTC packets\n", __func__);
      return (ENXIO);
    }
  }

  if (cfg->rtit_ctl & RTIT_CTL_CR3FILTER){
    if((pt_info.l0_ebx & CPUPT_CR3) == 0 ){
      printf("%s: CPU does not support CR3 filtering\n", __func__);
      return (ENXIO);
    }
  }

  if (cfg->rtit_ctl & RTIT_CTL_DIS_TNT){
    if((pt_info.l0_ebx & CPUPT_DIS_TNT) == 0 ){
      printf("%s: CPU does not support CR3 filtering\n", __func__);
      return (ENXIO);
    }
  }

  /* TODO: check support for other bits */
  pt_cpu->save_area.pt_ext_area.rtit_ctl |= cfg->rtit_ctl;

  if((error = pt_configure_ranges(pt_cpu, cfg)) != 0){
    return error;
  }

  memset(pt_cpu, 0, sizeof(struct pt_cpu));
  pt_cpu->vm = cpu->vm;
  if(pt_topa_prepare(pt_cpu)){
    dprintf("%s: failed to prepare ToPA buffer\n", __func__);
    pt_cpu->vm = NULL;
    return (-1);
  }

  /* Save hwt_td for kevent */
  pt_cpu->hwt_td = hwt_td;
  /* Prepare ToPA MSR values. */
  pt_ext->rtit_ctl = RTIT_CTL_TOPA;
  pt_ext->rtit_output_base = (uint64_t)vtophys(pt_cpu->buf.topa_hw);
  pt_ext->rtit_output_mask_ptrs = 0x7f; /* TODO: ? */
  /* Init header */
  hdr->xsave_bv = XFEATURE_ENABLED_PT;
  hdr->xcomp_bv = XFEATURE_ENABLED_PT | (1ULL << 63) /* compaction */;
  /* Enable tracing. */
  pt_ext->rtit_ctl |= RTIT_CTL_TRACEEN;

	return (0);
}

static void
pt_backend_enable(int cpu_id)
{
  dprintf("%s\n", __func__);

  pt_cpu_start(&pt_pcpu[cpu_id]);
}

static void
pt_backend_disable(int cpu_id)
{
  dprintf("%s\n", __func__);

  pt_cpu_stop(&pt_pcpu[cpu_id]);
}

static int
pt_backend_read(int cpu_id, int *curpage, vm_offset_t *curpage_offset){
  struct pt_cpu *pt_cpu = &pt_pcpu[cpu_id];
  dprintf("%s\n", __func__);

  if(pt_cpu->vm == NULL)
    return (-1);

  *curpage = pt_cpu->buf.curpage;
  *curpage_offset =  pt_cpu->buf.offset;

  return (0);
}

static void
pt_backend_dump(int cpu_id){
  return;
}


static struct hwt_backend_ops pt_ops = {
	.hwt_backend_init = pt_backend_init,
	.hwt_backend_deinit = pt_backend_deinit,

	.hwt_backend_configure = pt_backend_configure,

	.hwt_backend_enable = pt_backend_enable,
	.hwt_backend_disable = pt_backend_disable,

	.hwt_backend_read = pt_backend_read,
	.hwt_backend_dump = pt_backend_dump,
};

static void
pt_hwt_hook(struct thread *td, int func, void *arg){
  struct pt_cpu *cpu = &pt_pcpu[curcpu];
  switch(func){
  default:
  case HWT_SWITCH_IN:
  case HWT_SWITCH_OUT:
    pt_save_restore(cpu, func == HWT_SWITCH_OUT);
    break;
  }
}

void
pt_handle_toggle_intr(struct trapframe *tf){
  return;
}

/*
 * ToPA PMI kqueue task.
 */
static void
pt_buffer_ready(void *arg, int pending __unused)
{
	struct pt_cpu *cpu = arg;
	struct kevent kev;
	int ret __diagused;
	u_int uflags = 0x00ffffff;
	int64_t data = cpu->buf.offset;

	EV_SET(&kev, HWT_PT_BUF_RDY_EV, EVFILT_USER, 0,
         NOTE_TRIGGER | NOTE_FFCOPY | uflags, data, NULL);
	ret = kqfd_register(kqueue_fd, &kev, cpu->hwt_td, M_WAITOK);
  KASSERT(ret == 0, ("%s: kqueue fd register failed: %d\n", __func__, ret));
}

/*
 * ToPA PMI handler.
 */
static int
pt_topa_intr(struct trapframe *tf)
{
  int retval = 0;
  uint64_t reg;
  struct pt_cpu *pt_cpu;
  struct pt_buffer *buf;

  SDT_PROBE0(pt, , , topa__intr);
  /* TODO: handle possible double entry */
  /* Check ToPA PMI status on curcpu. */
  reg = rdmsr(MSR_IA_GLOBAL_STATUS);
  if((reg & GLOBAL_STATUS_FLAG_TRACETOPAPMI) == 0)
    return (retval);

  /*
   * Disable preemption.
   */
  critical_enter();

  retval = 1;
  pt_cpu = &pt_pcpu[curcpu];
  buf = &pt_cpu->buf;
  KASSERT(buf->topa_hw != NULL && pt_cpu->vm != NULL, ("%s: ToPA PMI interrupt with invalid pt_cpu", __func__ ));

  /* Disable tracing so we don't trace the PMI handler. */
  pt_cpu_stop(pt_cpu);
  /* Update buffer offset. */
  reg = rdmsr(MSR_IA32_RTIT_CTL);
	if (reg & RTIT_CTL_TRACEEN)
		reg = rdmsr(MSR_IA32_RTIT_OUTPUT_MASK_PTRS);
	else
		reg = 0;
	buf->curpage = (reg & 0xffffff80) >> 7;
	buf->offset = reg >> 32;

  /* Notify userspace. */
  TASK_INIT(&pt_cpu->task, 0, (task_fn_t *)pt_buffer_ready, pt_cpu);
  taskqueue_enqueue(taskqueue_hwt, &pt_cpu->task);

  /* Clear ToPA PMI status. */
  reg = rdmsr(MSR_IA_GLOBAL_STATUS_RESET);
  reg &= ~GLOBAL_STATUS_FLAG_TRACETOPAPMI;
  reg |= GLOBAL_STATUS_FLAG_TRACETOPAPMI;
  wrmsr(MSR_IA_GLOBAL_STATUS_RESET, reg);

  /* Re-enable tracing. */
  pt_cpu_start(pt_cpu);

  /*
   * Enable preemption.
   */
  critical_exit();

  return (retval);
}

static int
pt_init(void){
  u_int cp[4];

	dprintf("Enumerating part 1\n");

	cpuid_count(PT_CPUID, 0, cp);
	dprintf("%s: Maximum valid sub-leaf Index: %x\n", __func__, cp[0]);
	dprintf("%s: ebx %x\n", __func__, cp[1]);
	dprintf("%s: ecx %x\n", __func__, cp[2]);

  /* Save relevant cpuid info */
	pt_info.l0_eax = cp[0];
	pt_info.l0_ebx = cp[1];
	pt_info.l0_ecx = cp[2];

	dprintf("Enumerating part 2\n");

	cpuid_count(PT_CPUID, 1, cp);
	dprintf("%s: eax %x\n", __func__, cp[0]);
	dprintf("%s: ebx %x\n", __func__, cp[1]);

	pt_info.l1_eax = cp[0];
	pt_info.l1_ebx = cp[1];

  pt_ipinum = lapic_ipi_alloc(pt_cpu_handle_ipi);
  if (pt_ipinum < 0) {
    printf("%s: cannot allocate and IDT vector\n");
    return ENXIO;
  }

  return (0);
}


static bool
pt_supported(void){
  u_int cp[4];

  /* Intel SDM Vol. 3C, 33-30 */
  if ((cpu_stdext_feature & CPUID_STDEXT_PROCTRACE) == 0){
    printf("Intel PT: CPU does not support Intel Processor Trace\n");
    return (false);
  }

  /* Require XSAVE support. */
	if ((cpu_feature2 & CPUID2_XSAVE) == 0) {
		printf("Intel PT: XSAVE is not supported\n");
		return (false);
	}

  cpuid_count(0xd, 0x0, cp);
	if ((cp[0] & PT_XSAVE_MASK) != PT_XSAVE_MASK) {
		printf("Intel PT: CPU0 does not support X87 or SSE: %x", cp[0]);
		return (false);
	}

	cpuid_count(0xd, 0x1, cp);
	if ((cp[0] & (1 << 0)) == 0) {
		printf("Intel PT: XSAVE compaction is not supported\n");
		return (false);
	}
	if ((cp[0] & (1 << 3)) == 0) {
		printf("Intel PT: XSAVES/XRSTORS are not supported\n");
		return (false);
	}

  /* Require TOPA support. */
  cpuid_count(PT_CPUID, 0, cp);
  if((cp[2] & CPUPT_TOPA) == 0){
    printf("Intel PT: ToPA is not supported\n");
    return (false);
  }
  if((cp[2] & CPUPT_TOPA_MULTI) == 0){
    printf("Intel PT: multiple ToPA outputs are not supported\n");
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
    if(!pt_supported()){
      return (ENXIO);
    }
    pt_init();
    error = hwt_backend_register(&backend);
		if (error != 0) {
      printf("Intel PT: unable to register hwt backend, error %d\n", error);
			return (error);
		}
		mtx_init(&pt_mtx, "Intel PT", NULL, MTX_DEF);
    loaded = true;
		break;
	case MOD_UNLOAD:
    if(loaded){
      mtx_destroy(&pt_mtx);
      hwt_backend_unregister(&backend);
    }
		break;
	default:
		break;
	}
 
  return (0);
}

static moduledata_t pt_mod = {
	"intel_pt",
  pt_modevent,
  NULL
};

DECLARE_MODULE(intel_pt, pt_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_DEPEND(intel_pt, hwt, 1, 1, 1);
MODULE_VERSION(intel_pt, 1);
