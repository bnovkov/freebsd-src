#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/cdefs.h>
#include <sys/kernel.h>
#include <sys/patch.h>
#include <sys/mutex.h>
#include <sys/linker.h>
#include <sys/sx.h>

#include <machine/patch.h>

#include "linker_if.h"

static TAILQ_HEAD(, patch_set)	patch_list;
static struct mtx		patch_mutex;

int
patch_excluded(const char *name)
{
	if (strncmp(name, "patch_", 6) == 0)
		return (1);

	if (strncmp(name, "db_", 3) == 0 ||
	    strncmp(name, "kdb_", 4) == 0)
		return (1);

	if (strcmp(name, "owner_mtx") == 0 ||
	    strcmp(name, "owner_rm") == 0 ||
	    strcmp(name, "owner_rw") == 0 ||
	    strcmp(name, "owner_sx") == 0)
		return (1);

	if (strncmp(name, "__msan", 6) == 0 ||
	    strncmp(name, "kmsan_", 6) == 0)
		return (1);

	if (strcmp(name, "unwind_frame") == 0)
		return (1);

	return (0);
}

int
patch_load_set(patch_set_t *patch)
{
	patch_func_t *func;
	linker_symval_t symval;
	c_linker_sym_t sym;
	int error;

	for (func = patch->funcs; func->old_sym != NULL; func++) {
		if (patch_excluded(func->old_sym)) {
			printf("patch: %s is forbidden\n", func->old_sym);
			error = EPERM;
			break;
		}

		error = LINKER_LOOKUP_DEBUG_SYMBOL(linker_kernel_file, func->old_sym, &sym);
		if (error != 0) {
			printf("patch: unable to find symbol %s\n", func->old_sym);
			break;
		}

		error = LINKER_DEBUG_SYMBOL_VALUES(linker_kernel_file, sym, &symval);
		if (error != 0) {
			printf("patch: unable to resolve symbol %s\n", func->old_sym);
			break;
		}

		func->old_addr = symval.value;
		func->old_size = symval.size;

		error = patch_validate_target(func);
		if (error != 0) {
			printf("patch: %s cannot be patched\n", func->old_sym);
			break;
		}
	}

	if (error == 0) {
		mtx_lock(&patch_mutex);

		// Debug only
		for (func = patch->funcs; func->old_sym != NULL; func++) {
			printf("patch: %s <%p>  ==>  <%p>\n",
				func->old_sym, func->old_addr, func->new_addr);
		}

		// TODO: Write trampolines here
		TAILQ_INSERT_TAIL(&patch_list, patch, link);
		patch->enabled = true;

		mtx_unlock(&patch_mutex);
	}

	return (error);
}

int
patch_unload_set(patch_set_t *patch)
{
	mtx_lock(&patch_mutex);

	if (patch->enabled) {
		// TODO: Restore the old instructions here

		TAILQ_REMOVE(&patch_list, patch, link);
		patch->enabled = false;
	}

	mtx_unlock(&patch_mutex);
	return (0);
}

static void
patch_init(void *dummy __unused)
{
	TAILQ_INIT(&patch_list);
	mtx_init(&patch_mutex, "patch", NULL, MTX_DEF);

	printf("patch: kernel patching available\n");
}

SYSINIT(patch, SI_SUB_KLD, SI_ORDER_ANY, patch_init, NULL);
