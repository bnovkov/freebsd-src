#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/systm.h>

#include <machine/cpufunc.h>
#include <machine/md_var.h>
#include <machine/patch.h>

#define AMD64_JMPLEN 5

int
patch_validate_func(patch_func_t *func)
{
	intptr_t offset;

	if (func->old_size <= AMD64_JMPLEN)
		return (ENOSPC);

	offset = (intptr_t)func->new_addr - ((intptr_t)func->old_addr + AMD64_JMPLEN);
	if (offset < INT32_MIN || offset > INT32_MAX)
		return (ERANGE);

	return (0);
}

static void
patch_write_text(void *addr, uint8_t *insn, size_t size)
{
	bool wp = disable_wp();
	memcpy(addr, insn, size);
	restore_wp(wp);
}

int
patch_apply_func(patch_func_t *func, void *arg __unused)
{
	return (0);
}

int
patch_rollback_func(patch_func_t *func, void *arg __unused)
{
	return (0);
}
