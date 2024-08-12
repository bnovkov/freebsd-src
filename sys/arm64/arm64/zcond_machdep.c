#include <sys/param.h>
#include <sys/systm.h>
#include <sys/zcond.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/cpufunc.h>
#include <machine/zcond.h>

extern struct pmap zcond_patching_pmap;

void
zcond_before_patch(void)
{
}

void
zcond_after_patch(void)
{
}

void
zcond_before_rendezvous(struct zcond_md_ctxt *ctxt)
{
    ctxt->ttbr0 = READ_SPECIALREG(ttbr0_el1);
    set_ttbr0(pmap_to_ttbr0(&zcond_patching_pmap));
}

void
zcond_after_rendezvous(struct zcond_md_ctxt *ctxt)
{
    set_ttbr0(ctxt->ttbr0);
}

static void
insn_nop(uint8_t insn[])
{
	int i;
	for (i = 0; i < ZCOND_MAX_INSN_SIZE; i++) {
		insn[i] = nop_bytes[i];
	}
}

static void
insn_jmp(uint8_t insn[], vm_offset_t offset)
{
	vm_offset_t imm26;
	uint32_t instr;
	int i;

	imm26 = offset >> 2;
	instr = (imm26 & 0x3fffffful) | 0x14000000;

	for (i = 0; i < ZCOND_MAX_INSN_SIZE; i++) {
		insn[i] = (instr >> (i * 8)) & 0xFF;
	}
}

void
zcond_get_patch_insn(struct patch_point *p, uint8_t insn[], size_t *size)
{
	uint8_t *patch_addr;
	vm_offset_t offset;

	patch_addr = (uint8_t *)p->patch_addr;
	*size = ZCOND_MAX_INSN_SIZE;
	printf("patch opcode: %02hhx at %p", *patch_addr, patch_addr);
	if (*patch_addr == nop_bytes[0]) {
		offset = p->lbl_true_addr - p->patch_addr;
		insn_jmp(insn, offset);
	} else if ((*(patch_addr + 3) & ~(0x3)) == 0x14) {
		insn_nop(insn);
	} else {
		panic("unexpected opcode: %02hhx", *patch_addr);
	}
}
