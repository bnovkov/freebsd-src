//#include <sys/param.h>
//#include <sys/cdefs.h>
//#include <sys/systm.h>
//
//#include <machine/cpufunc.h>
//#include <machine/md_var.h>
//
//#define KPATCH_INTERNAL
//#include <sys/kpatch.h>
//
//static inline intptr_t
//patch_target_offset(patch_func_t *func)
//{
//	return (intptr_t)func->new_addr - ((intptr_t)func->old_addr + AMD64_JMP_LEN);
//}
//
//int
//patch_validate_func(patch_func_t *func)
//{
//	intptr_t offset;
//
//	if (func->old_size <= AMD64_JMP_LEN)
//		return (ENOSPC);
//
//	offset = patch_target_offset(func);
//	if (offset < INT32_MIN || offset > INT32_MAX)
//		return (ERANGE);
//
//	return (0);
//}
//
//static void
//patch_write_text(void *addr, uint8_t *insn, size_t size)
//{
//	bool wp = disable_wp();
//	memcpy(addr, insn, size);
//	restore_wp(wp);
//}
//
//void
//patch_install_trampoline(patch_func_t *func)
//{
//	int32_t offset;
//	uint8_t insn[AMD64_JMP_LEN];
//
//	// Save previous instruction
//	memcpy(func->old_text, func->old_addr, AMD64_JMP_LEN);
//
//	// Prepare jump to the new addr
//	insn[0] = AMD64_JMP_OPCODE;
//	offset = patch_target_offset(func);
//	memcpy(&insn[1], &offset, sizeof(offset));
//
//	// Overwrite the prologue with the trampoline
//	patch_write_text(func->old_addr, insn, AMD64_JMP_LEN);
//}
//
//void
//patch_restore_trampoline(patch_func_t *func)
//{
//	patch_write_text(func->old_addr, func->old_text, AMD64_JMP_LEN);
//}
