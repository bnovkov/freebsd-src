#include <sys/types.h>
#include <sys/zcond.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>

#include <machine/cpufunc.h>
#include <machine/zcond.h>
#include <vm/vm_page.h>
#include <machine/pmap.h>

struct pmap zcond_pmap;

void
zcond_before_patch(void)
{
}

void
zcond_after_patch(void)
{
	mfence();
}

void
zcond_before_rendezvous(struct zcond_md_ctxt *ctxt)
{

	ctxt->cr3 = rcr3();
	load_cr3(zcond_pmap.pm_cr3);
}

void
zcond_after_rendezvous(struct zcond_md_ctxt *ctxt)
{
	load_cr3(ctxt->cr3);
	invltlb();
}

static void
insn_nop(uint8_t insn[], size_t size)
{
	int i;

	if (size == ZCOND_INSN_SHORT_SIZE) {
		for (i = 0; i < ZCOND_INSN_SHORT_SIZE; i++) {
			insn[i] = nop_short_bytes[i];
		}
	} else {
		for (i = 0; i < ZCOND_INSN_LONG_SIZE; i++) {
			insn[i] = nop_long_bytes[i];
		}
	}
}

static void
insn_jmp(uint8_t insn[], size_t size, vm_offset_t offset)
{
	int i;
	if (size == 2) {
		insn[0] = ZCOND_JMP_SHORT_OPCODE;
		insn[1] = offset;
	} else {
		insn[0] = ZCOND_JMP_LONG_OPCODE;
		for (i = 0; i < ZCOND_INSN_LONG_SIZE - 1; i++) {
			insn[i + 1] = (offset >> (i * 8)) & 0xFF;
		}
	}
}

void
zcond_get_patch_insn(struct patch_point *p, uint8_t insn[], size_t *size)
{
	uint8_t *patch_addr = (uint8_t *)p->patch_addr;
	vm_offset_t offset;

	if (*patch_addr == nop_short_bytes[0]) {
		// two byte nop
		*size = ZCOND_INSN_SHORT_SIZE;
		goto nop;
	} else if (*patch_addr == nop_long_bytes[0]) {
		*size = ZCOND_INSN_LONG_SIZE;
		goto nop;
	} else if (*patch_addr == ZCOND_JMP_SHORT_OPCODE) {
		// two byte jump
		*size = ZCOND_INSN_SHORT_SIZE;
		goto jmp;
	} else if (*patch_addr == ZCOND_JMP_LONG_OPCODE) {
		// five byte jump
		*size = ZCOND_INSN_LONG_SIZE;
		goto jmp;
	} else {
		panic("unexpected opcode: %02hhx", *patch_addr);
	}

nop:
	// replace nop with jmp
	offset = p->lbl_true_addr - p->patch_addr - *size;
	insn_jmp(insn, *size, offset);
	return;

jmp:
	// replace jmp with nop
	insn_nop(insn, *size);
}


/**********************
 * pmap functionality *
***********************/

static vm_offset_t zcond_patch_va;

static void
zcond_pmap_init(const void *unused) {
    vm_offset_t kern_start, kern_end;
    vm_page_t dummy_page;

    kern_start = virtual_avail;
    kern_end = kernel_vm_end;

	memset(&zcond_pmap, 0, sizeof(zcond_pmap));
	PMAP_LOCK_INIT(&zcond_pmap);
	pmap_pinit(&zcond_pmap);
	pmap_copy(&zcond_pmap, kernel_pmap, kern_start,
	    kern_end - kern_start, kern_start);

    zcond_patch_va = kva_alloc(PAGE_SIZE);
    dummy_page = vm_page_alloc_noobj(VM_ALLOC_WIRED);
    pmap_enter(&zcond_pmap, zcond_patch_va, dummy_page, VM_PROT_WRITE, PMAP_ENTER_WIRED, 0);
    kva_free(zcond_patch_va, PAGE_SIZE);
}
SYSINIT(zcond_pmap, SI_SUB_ZCOND, SI_ORDER_SECOND, zcond_pmap_init, NULL);

void
pmap_qenter_zcond(vm_page_t m) {
    pt_entry_t oldpte, pa;
    pt_entry_t *pte;
    int cache_bits;

    oldpte = 0;
    pte = pmap_pte(&zcond_pmap, zcond_patch_va);

    cache_bits = pmap_cache_bits(&zcond_pmap, m->md.pat_mode, false);
    pa = VM_PAGE_TO_PHYS(m) | cache_bits;
    if ((*pte & (PG_FRAME | X86_PG_PTE_CACHE)) != pa) {
            oldpte |= *pte;
            pte_store(pte, pa | pg_g | pg_nx | X86_PG_A |
                X86_PG_M | X86_PG_RW | X86_PG_V);
    }

    if (__predict_false((oldpte & X86_PG_V) != 0))
            pmap_invalidate_range(&zcond_pmap, zcond_patch_va, zcond_patch_va + PAGE_SIZE);
}

void
pmap_qremove_zcond(void) {
    pt_entry_t *pte;

    pte = pmap_pte(&zcond_pmap, zcond_patch_va);
    pte_clear(pte);
}

vm_offset_t zcond_get_patch_va(void) {
    return zcond_patch_va;
}

