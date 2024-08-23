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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cpuset.h>
#include <sys/kernel.h>
#include <sys/patch.h>
#include <sys/smp.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>

#include <machine/patch.h>

struct patch_arg {
	int patching_cpu;
	vm_offset_t *vas;
	uint8_t **insns;
	size_t *sizes;
	size_t cnt;
	struct kpatch_md_ctxt md_ctxt;
};

static vm_offset_t patch_addr;

static void
patch_init(void *arg)
{
	patch_addr = kpatch_get_va();
}

SYSINIT(patch, SI_SUB_PATCH, SI_ORDER_SECOND, patch_init, NULL);

static void
__patch(void *arg)
{
	struct patch_arg *data;
	vm_offset_t va;
	vm_page_t patch_page;
	uint8_t *insn;
	size_t size;
	size_t page_overflow;
	int i;

	data = (struct patch_arg *)arg;
	for (i = 0; i < data->cnt; i++) {
		va = data->vas[i];
		insn = data->insns[i];
		size = data->sizes[i];

		if (!kpatch_va_valid(va)) {
			panic("%s: va %lx not inside .text section", __func__,
			    va);
		}

		if ((va & (~PAGE_MASK)) != ((va + size) & (~PAGE_MASK))) {
			page_overflow = (va + size) & PAGE_MASK;
		} else {
			page_overflow = 0;
		}

		KASSERT((page_overflow < PAGE_SIZE && page_overflow > 0),
		    ("%s: patching instruction over more than 2 pages",
			__func__));

		patch_page = PHYS_TO_VM_PAGE(vtophys(va));
		kpatch_setup(patch_page, &data->md_ctxt);
		memcpy((void *)(patch_addr + (va & PAGE_MASK)), insn,
		    size - page_overflow);
		kpatch_teardown(&data->md_ctxt);

		if (page_overflow != 0) {
			va += size - page_overflow;
			insn += size - page_overflow;
			patch_page = PHYS_TO_VM_PAGE(vtophys(va));

			kpatch_setup(patch_page, &data->md_ctxt);
			memcpy((void *)(patch_addr + (va & PAGE_MASK)), insn,
			    page_overflow);
			kpatch_teardown(&data->md_ctxt);
		}
	}
}

static void
rendezvous_action(void *arg)
{
	struct patch_arg *data;

	data = (struct patch_arg *)arg;

	if (data->patching_cpu == curcpu) {
		__patch(data);
	}
}

void
kpatch_text_single(vm_offset_t va, uint8_t *insn, size_t size)
{
	kpatch_text_batch(&va, &insn, &size, 1);
}

void
kpatch_text_batch(vm_offset_t *vas, uint8_t **insns, size_t *sizes, size_t cnt)
{
	struct patch_arg arg = { .patching_cpu = curcpu,
		.vas = vas,
		.insns = insns,
		.sizes = sizes,
		.cnt = cnt };

	smp_rendezvous(NULL, rendezvous_action, NULL, &arg);
}
