/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 Marko Vlaić <mvlaic@freebsd.org>
 *
 * This code was developed as a Google Summer of Code 2024. project
 * under the guidance of Bojan Novković <bnovkov@freebsdorg>.
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
#include <sys/cpuset.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/linker_set.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/refcount.h>
#include <sys/sbuf.h>
#include <sys/smp.h>
#include <sys/sysctl.h>
#include <sys/zcond.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>

#include <machine/atomic.h>
#include <machine/cpufunc.h>

struct zcond_patch_arg {
	int patching_cpu;
	struct zcond *cond;
	struct zcond_md_ctxt *md_ctxt;
	bool enable;
};

MALLOC_DECLARE(M_ZCOND);
MALLOC_DEFINE(M_ZCOND, "zcond", "malloc for the zcond subsystem");

static void
zcond_load_patch_points(linker_file_t lf)
{
	struct patch_point *begin, *end;
	struct patch_point *ins_p;
	struct zcond *owning_zcond;

	if (linker_file_lookup_set(lf, __XSTRING(ZCOND_LINKER_SET), &begin,
		&end, NULL) == 0) {
		for (ins_p = begin; ins_p < end; ins_p++) {
			owning_zcond = ins_p->zcond;

			if (owning_zcond->patch_points.slh_first == NULL) {
				SLIST_INIT(&owning_zcond->patch_points);
			}

			SLIST_INSERT_HEAD(&owning_zcond->patch_points, ins_p,
			    next);
		}
	}
}

static void
zcond_kld_load(void *arg __unused, struct linker_file *lf)
{
	zcond_load_patch_points(lf);
}

static int
zcond_load_patch_points_cb(linker_file_t lf, void *arg __unused)
{
	zcond_load_patch_points(lf);
	return (0);
}

/*
 * Collect patch_points from the __zcond_table ELF section into a list.
 * Prepare a CPU local copy of the kernel_pmap, used to safely patch
 * an instruction.
 */
static vm_offset_t
    patch_addr; /* When performing a patch on a zcond, each page containing a
		   patch_point is patched to this address. */
static void
zcond_init(const void *unused)
{
	EVENTHANDLER_REGISTER(kld_load, zcond_kld_load, NULL,
	    EVENTHANDLER_PRI_ANY);
	linker_file_foreach(zcond_load_patch_points_cb, NULL);
	patch_addr = zcond_get_patch_va();
}
SYSINIT(zcond, SI_SUB_ZCOND, SI_ORDER_SECOND, zcond_init, NULL);

/*
 * Patch all patch_points belonging to cond.
 */
static void
zcond_patch(struct zcond *cond, bool enable)
{
	struct patch_point *p;
	vm_page_t patch_page;
	uint8_t insn[ZCOND_MAX_INSN_SIZE];
	size_t insn_size;

	SLIST_FOREACH(p, &cond->patch_points, next) {
		zcond_get_patch_insn(p, insn, &insn_size);

		patch_page = PHYS_TO_VM_PAGE(vtophys(p->patch_addr));
		pmap_qenter_zcond(patch_page);

		zcond_before_patch();
		memcpy((void *)(patch_addr + (p->patch_addr & PAGE_MASK)),
		    &insn[0], insn_size);
		zcond_after_patch();
	}
}

static void
rendezvous_setup(void *arg)
{
	struct zcond_patch_arg *data;

	data = (struct zcond_patch_arg *)arg;

	if (data->patching_cpu == curcpu) {
		zcond_before_rendezvous(data->md_ctxt);
	}
}

static void
rendezvous_action(void *arg)
{
	struct zcond_patch_arg *data;

	data = (struct zcond_patch_arg *)arg;

	if (data->patching_cpu == curcpu) {
		zcond_patch(data->cond, data->enable);
	}
}

static void
rendezvous_teardown(void *arg)
{
	struct zcond_patch_arg *data;

	data = (struct zcond_patch_arg *)arg;

	if (data->patching_cpu == curcpu) {
		zcond_after_rendezvous(data->md_ctxt);
	}
}

void
__zcond_toggle(struct zcond *cond, bool enable)
{
	struct zcond_md_ctxt ctxt;

	if (enable && refcount_acquire(&cond->refcnt) > 0) {
		return;
	} else if (!enable && !refcount_release_if_not_last(&cond->refcnt)) {
		return;
	}

	struct zcond_patch_arg arg = { .patching_cpu = curcpu,
		.cond = cond,
		.md_ctxt = &ctxt,
		.enable = enable };

	smp_rendezvous(rendezvous_setup, rendezvous_action, rendezvous_teardown,
	    &arg);
	zcond_after_rendezvous(&ctxt);
}

/*
 * Testing code.
 */
DEFINE_ZCOND_TRUE(cond1);
DEFINE_ZCOND_FALSE(cond2);

static int
trigger_zcond_test(SYSCTL_HANDLER_ARGS)
{
	struct sbuf buf;
	sbuf_new_for_sysctl(&buf, NULL, 256, req);

	sbuf_printf(&buf, "zcond test start\n");
	if (zcond_true(cond1)) {
		sbuf_printf(&buf, "cond 1 true\n");
	} else {
		sbuf_printf(&buf, "cond 1 false\n");
	}

	if (zcond_true(cond2)) {
		sbuf_printf(&buf, "cond2 true\n");
	} else {
		sbuf_printf(&buf, "cond2 false\n");
	}

	sbuf_finish(&buf);
	sbuf_delete(&buf);

	return (0);
}

static int
trigger_zcond_test2(SYSCTL_HANDLER_ARGS)
{
	struct sbuf buf;
	sbuf_new_for_sysctl(&buf, NULL, 256, req);

	sbuf_printf(&buf, "zcond test 2 start\n");
	if (zcond_true(cond1)) {
		sbuf_printf(&buf, "cond 1 true %s\n", __func__);
	}

	// simulate long jump with nops
	/*asm (
	    ".nops 512\n\t":::
	);*/

	sbuf_finish(&buf);
	sbuf_delete(&buf);
	return (0);
}

static int
trigger_zcond_test3(SYSCTL_HANDLER_ARGS)
{
	struct sbuf buf;
	sbuf_new_for_sysctl(&buf, NULL, 256, req);

	sbuf_printf(&buf, "zcond test 3 start\n");
	if (zcond_false(cond1)) {
		sbuf_printf(&buf, "cond1 false\n");
	} else {
		sbuf_printf(&buf, "cond1 true\n");
	}

	if (zcond_false(cond2)) {
		sbuf_printf(&buf, "cond2 false\n");
	} else {
		sbuf_printf(&buf, "cond2 true\n");
	}

	sbuf_finish(&buf);
	sbuf_delete(&buf);

	return (0);
}

static int
zcond_list_inspection_points(SYSCTL_HANDLER_ARGS)
{
	struct sbuf buf;
	sbuf_new_for_sysctl(&buf, NULL, 1024, req);

	printf("&cond1 = %#08lx | &cond2 = %#08lx\n", (unsigned long)&cond1,
	    (unsigned long)&cond2);

	sbuf_printf(&buf, "inspection points for cond1:\n");
	struct patch_point *p;
	SLIST_FOREACH(p, &cond1.cond.patch_points, next) {
		sbuf_printf(&buf,
		    "patch_addr = %#08lx | jump_addr = %#08lx | zcond_ptr = %p\n",
		    p->patch_addr, p->lbl_true_addr, p->zcond);
	}

	sbuf_printf(&buf, "inspection points for cond2:\n");
	SLIST_FOREACH(p, &cond2.cond.patch_points, next) {
		sbuf_printf(&buf,
		    "patch_addr = %#08lx | jump_addr = %#08lx | zcond_ptr = %p\n",
		    p->patch_addr, p->lbl_true_addr, p->zcond);
	}

	sbuf_finish(&buf);
	sbuf_delete(&buf);

	return (0);
}

static int
zcond1_disable(SYSCTL_HANDLER_ARGS)
{
	struct sbuf buf;
	sbuf_new_for_sysctl(&buf, NULL, 256, req);

	zcond_disable(cond1);
	sbuf_printf(&buf, "cond1 disabled\n");

	return (0);
}

static int
zcond1_enable(SYSCTL_HANDLER_ARGS)
{
	struct sbuf buf;
	sbuf_new_for_sysctl(&buf, NULL, 256, req);

	zcond_enable(cond1);
	sbuf_printf(&buf, "cond1 enabled\n");

	sbuf_finish(&buf);
	sbuf_delete(&buf);
	return (0);
}

static int
zcond2_disable(SYSCTL_HANDLER_ARGS)
{
	struct sbuf buf;
	sbuf_new_for_sysctl(&buf, NULL, 256, req);

	zcond_disable(cond2);
	sbuf_printf(&buf, "cond2 disabled\n");

	return (0);
}

static int
zcond2_enable(SYSCTL_HANDLER_ARGS)
{
	struct sbuf buf;
	sbuf_new_for_sysctl(&buf, NULL, 256, req);

	zcond_enable(cond2);
	sbuf_printf(&buf, "cond2 enabled\n");

	sbuf_finish(&buf);
	sbuf_delete(&buf);

	return (0);
}
SYSCTL_PROC(_kern, OID_AUTO, zcond, CTLFLAG_RD | CTLTYPE_STRING, NULL, 0,
    trigger_zcond_test, "I", "trigger zcond test");
SYSCTL_PROC(_kern, OID_AUTO, zcond2, CTLFLAG_RD | CTLTYPE_STRING,
    SYSCTL_NULL_INT_PTR, 0, trigger_zcond_test2, "I",
    "trigger second zcond test");
SYSCTL_PROC(_kern, OID_AUTO, zcond3, CTLFLAG_RD | CTLTYPE_STRING,
    SYSCTL_NULL_INT_PTR, 0, trigger_zcond_test3, "I",
    "trigger third zcond test");
SYSCTL_PROC(_kern, OID_AUTO, zcond_ins_p, CTLFLAG_RD | CTLTYPE_STRING,
    SYSCTL_NULL_INT_PTR, 0, zcond_list_inspection_points, "I",
    "list cond1 inspection points");
SYSCTL_PROC(_kern, OID_AUTO, zcond1_enable, CTLFLAG_RD | CTLTYPE_STRING,
    SYSCTL_NULL_INT_PTR, 0, zcond1_enable, "I", "enable zcond1");
SYSCTL_PROC(_kern, OID_AUTO, zcond1_disable, CTLFLAG_RD | CTLTYPE_STRING,
    SYSCTL_NULL_INT_PTR, 0, zcond1_disable, "I", "disable zcond1");
SYSCTL_PROC(_kern, OID_AUTO, zcond2_enable, CTLFLAG_RD | CTLTYPE_STRING,
    SYSCTL_NULL_INT_PTR, 0, zcond2_enable, "I", "enable zcond2");
SYSCTL_PROC(_kern, OID_AUTO, zcond2_disable, CTLFLAG_RD | CTLTYPE_STRING,
    SYSCTL_NULL_INT_PTR, 0, zcond2_disable, "I", "disable zcond2");
