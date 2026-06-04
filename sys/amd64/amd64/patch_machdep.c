#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/systm.h>

#include <machine/patch.h>

#define AMD64_JMPLEN 5

int
patch_validate_target(patch_func_t *func)
{
	intptr_t offset;

	if (func->old_size <= AMD64_JMPLEN)
		return (ENOSPC);

	offset = (intptr_t)func->new_addr - ((intptr_t)func->old_addr + AMD64_JMPLEN);
	if (offset < INT32_MIN || offset > INT32_MAX)
		return (ERANGE);

	return (0);
}
