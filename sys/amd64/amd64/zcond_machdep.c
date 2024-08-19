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
#include <sys/domain.h>
#include <sys/domainset.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/vmem.h>
#include <sys/zcond.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/uma.h>
#include <vm/vm_domainset.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>
#include <vm/vm_pagequeue.h>

#include <machine/cpufunc.h>
#include <machine/pmap.h>
#include <machine/zcond.h>

static struct pmap zcond_pmap;
static vm_offset_t zcond_patch_va;
static pt_entry_t *zcond_patch_pte;

static uint8_t insn[ZCOND_MAX_INSN_SIZE];

static uint8_t *
insn_nop(size_t size)
{
	if (size == ZCOND_INSN_SHORT_SIZE) {
		return &nop_short_bytes[0];
	}
	return &nop_long_bytes[0];
}

static uint8_t *
insn_jmp(size_t size, vm_offset_t patch_addr, vm_offset_t lbl_true_addr)
{
	int i;
	vm_offset_t offset;

	offset = lbl_true_addr - patch_addr - size;

	if (size == ZCOND_INSN_SHORT_SIZE) {
		insn[0] = ZCOND_JMP_SHORT_OPCODE;
		insn[1] = offset;
	} else {
		insn[0] = ZCOND_JMP_LONG_OPCODE;
		for (i = 0; i < ZCOND_INSN_LONG_SIZE - 1; i++) {
			insn[i + 1] = (offset >> (i * 8)) & 0xFF;
		}
	}

	return &insn[0];
}

/**********************
 * pmap functionality *
 ***********************/
static pt_entry_t *
zcond_init_pte(void)
{
	vm_page_t dummy_page;
	int domain;
	pml5_entry_t *pml5e;
	pml4_entry_t *pml4e;
	pdp_entry_t *pdpe;
	pd_entry_t *pde;
	pt_entry_t *pte;
	vm_pindex_t pml5_idx, pml4_idx, pdp_idx, pd_idx;
	vm_paddr_t mphys;
	extern int la57;
	bool is_la57;

	domain = PCPU_GET(domain);
	vmem_alloc(VM_DOMAIN(domain)->vmd_kernel_nofree_arena, PAGE_SIZE,
	    M_BESTFIT | M_WAITOK, &zcond_patch_va);
	dummy_page = vm_page_alloc_noobj_domain(domain,
	    VM_ALLOC_WIRED | VM_ALLOC_NOFREE);
	pmap_enter(&zcond_pmap, zcond_patch_va, dummy_page, VM_PROT_WRITE,
	    PMAP_ENTER_WIRED, 0);

	is_la57 = false;
	if (zcond_pmap.pm_type == PT_X86) {
		is_la57 = la57;
	}

	pml4_idx = pmap_pml4e_index(zcond_patch_va);
	if (is_la57) {
		pml5_idx = pmap_pml5e_index(zcond_patch_va);
		pml5e = &zcond_pmap.pm_pmltopu[pml5_idx];
		KASSERT(*pml5e != 0,
		    ("%s: va %#jx pml5e == 0", __func__, zcond_patch_va));
		mphys = *pml5e & PG_FRAME;

		pml4e = (pml4_entry_t *)PHYS_TO_DMAP(mphys);
		pml4e = &pml4e[pml4_idx];
	} else {
		pml4e = &zcond_pmap.pm_pmltop[pml4_idx];
	}

	KASSERT(*pml4e != 0,
	    ("%s: va %#jx pml4e == 0", __func__, zcond_patch_va));
	mphys = *pml4e & PG_FRAME;

	pdpe = (pdp_entry_t *)PHYS_TO_DMAP(mphys);
	pdp_idx = pmap_pdpe_index(zcond_patch_va);
	pdpe += pdp_idx;
	KASSERT(*pdpe != 0,
	    ("%s: va %#jx pdpe == 0", __func__, zcond_patch_va));
	mphys = *pdpe & PG_FRAME;

	pde = (pd_entry_t *)PHYS_TO_DMAP(mphys);
	pd_idx = pmap_pde_index(zcond_patch_va);
	pde += pd_idx;
	KASSERT(*pde != 0, ("%s: va %#jx pde == 0", __func__, zcond_patch_va));
	mphys = *pde & PG_FRAME;

	pte = (pt_entry_t *)PHYS_TO_DMAP(mphys);
	pte += pmap_pte_index(zcond_patch_va);

	return (pte);
}

static void
zcond_pmap_init(const void *unused)
{
	vm_offset_t kern_start, kern_end;

	kern_start = virtual_avail;
	kern_end = kernel_vm_end;

	memset(&zcond_pmap, 0, sizeof(zcond_pmap));
	PMAP_LOCK_INIT(&zcond_pmap);
	pmap_pinit(&zcond_pmap);
	pmap_copy(&zcond_pmap, kernel_pmap, kern_start, kern_end - kern_start,
	    kern_start);

	zcond_patch_pte = zcond_init_pte();
}
SYSINIT(zcond_pmap, SI_SUB_ZCOND, SI_ORDER_FIRST, zcond_pmap_init, NULL);

static void
zcond_qenter(vm_page_t m)
{
	pt_entry_t pa;
	int cache_bits;

	cache_bits = pmap_cache_bits(&zcond_pmap, m->md.pat_mode, false);
	pa = VM_PAGE_TO_PHYS(m) | cache_bits;
	if ((*zcond_patch_pte & (PG_FRAME | X86_PG_PTE_CACHE)) != pa) {
		pte_store(zcond_patch_pte,
		    pa | pg_nx | X86_PG_A | X86_PG_M | X86_PG_RW | X86_PG_V);
	}

	invlpg(zcond_patch_va);
}

vm_offset_t
zcond_get_patch_va(void)
{
	return (zcond_patch_va);
}

void
zcond_before_patch(vm_page_t patch_page, struct zcond_md_ctxt *ctxt)
{
	zcond_qenter(patch_page);
	ctxt->cr3 = rcr3();
	load_cr3(zcond_pmap.pm_cr3);
}

void
zcond_after_patch(struct zcond_md_ctxt *ctxt)
{
	mfence();
	load_cr3(ctxt->cr3);
	pte_clear(zcond_patch_pte);
	invltlb();
}

uint8_t *
zcond_get_patch_insn(vm_offset_t patch_addr, vm_offset_t lbl_true_addr,
    size_t *size)
{
	uint8_t *pa;

	pa = (uint8_t *)patch_addr;
	if (*pa == nop_short_bytes[0]) {
		/* two byte nop */
		*size = ZCOND_INSN_SHORT_SIZE;
		return insn_jmp(*size, patch_addr, lbl_true_addr);
	} else if (*pa == nop_long_bytes[0]) {
		*size = ZCOND_INSN_LONG_SIZE;
		return insn_jmp(*size, patch_addr, lbl_true_addr);
	} else if (*pa == ZCOND_JMP_SHORT_OPCODE) {
		/* two byte jump */
		*size = ZCOND_INSN_SHORT_SIZE;
		return insn_nop(*size);
	} else if (*pa == ZCOND_JMP_LONG_OPCODE) {
		/* five byte jump */
		*size = ZCOND_INSN_LONG_SIZE;
		return insn_nop(*size);
	} else {
		panic("%s: unexpected opcode: %02hhx", __func__, *pa);
	}
}
