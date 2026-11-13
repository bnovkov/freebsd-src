#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/systm.h>
#include <sys/proc.h>

#include <machine/cpufunc.h>
#include <machine/md_var.h>
#include <machine/frame.h>

#define KPATCH_INTERNAL
#include <sys/kpatch.h>

static inline intptr_t
kpatch_target_offset(struct kpatch_func *func)
{
	return (intptr_t)func->new_addr - ((intptr_t)func->old_addr + AMD64_JMP_LEN);
}

int
kpatch_func_validate(struct kpatch_func *func)
{
	intptr_t offset;
	uint8_t *insn = (uint8_t *)func->old_addr;

	if (func->old_size <= AMD64_JMP_LEN)
		return (ENOSPC);

	offset = kpatch_target_offset(func);
	if (offset < INT32_MIN || offset > INT32_MAX)
		return (ERANGE);

	if (insn[0] != AMD64_PUSH_RBP_OPCODE)
		return (ENOTSUP);

	return (0);
}

static void
kpatch_write_text(void *addr, uint8_t *insn, size_t size)
{
	bool wp = disable_wp();
	memcpy(addr, insn, size);
	restore_wp(wp);
}

void
kpatch_install_trap(struct kpatch_func *func)
{
	uint8_t insn = AMD64_INT3_OPCODE;
	memcpy(func->old_text, func->old_addr, AMD64_JMP_LEN);
	kpatch_write_text(func->old_addr, &insn, 1);
}

void
kpatch_install_trampoline(struct kpatch_func *func)
{
	int32_t offset;
	uint8_t insn[AMD64_JMP_LEN];

	// Save previous instruction
	memcpy(func->old_text, func->old_addr, AMD64_JMP_LEN);

	// Prepare jump to the new addr
	insn[0] = AMD64_JMP_OPCODE;
	offset = kpatch_target_offset(func);
	memcpy(&insn[1], &offset, sizeof(offset));

	// Overwrite the prologue with the trampoline
	kpatch_write_text(func->old_addr, insn, AMD64_JMP_LEN);
}

void
kpatch_restore_trampoline(struct kpatch_func *func)
{
	kpatch_write_text(func->old_addr, func->old_text, AMD64_JMP_LEN);
}

void
kpatch_flush_icache(void)
{
	wbinvd();
}

int
kpatch_trap_handler(struct trapframe *tf)
{
	struct kpatch_func *func;
	uintptr_t addr;
	int flag;

	addr = tf->tf_rip - 1;

	func = kpatch_func_find(addr);
	if (func == NULL)
		return (-1);

	if (func->patch->active_id < 0) {
		printf("kpatch: Invalid set active id!\n");
		return (1);
	}

	flag = 1ULL << func->patch->active_id;
	if (curthread->td_kpatch_mask & flag) {
		/*
		 * Thread is migrated to the active patch
		 */
		tf->tf_rip = (register_t)func->new_addr;
		return (0);
	}

	/*
	 * Thread is still using the previous code
	 */
	return (1);
}
