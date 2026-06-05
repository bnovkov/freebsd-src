#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/cdefs.h>
#include <sys/kernel.h>
#include <sys/patch.h>
#include <sys/mutex.h>
#include <sys/linker.h>
#include <sys/smp.h>

#include <machine/patch.h>

#include "linker_if.h"

struct patch_param {
	patch_set_t *patch;
	int cpuid;
	int (*op)(patch_func_t *, void *);
	void *arg;
};

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

static int
patch_iterate_set(patch_set_t *patch, int (*op)(patch_func_t *, void *),
		  void *arg)
{
	patch_func_t *func;
	int error;

	for (func = patch->funcs; func->old_sym != NULL; func++) {
		error = op(func, arg);
		if (error != 0)
			return (error);
	}

	return (0);
}

static void
patch_rendezvous_action(void *arg)
{
	struct patch_param *param = (struct patch_param *)arg;

	if (curcpu == param->cpuid) {
		patch_iterate_set(param->patch, param->op, param->arg);
	}

	// TODO: Flush icache here
}

static int
patch_resolve_func(patch_func_t *func, void *arg)
{
	linker_symval_t symval;
	c_linker_sym_t sym;
	int error;

	if (patch_excluded(func->old_sym)) {
		printf("patch: %s is forbidden\n", func->old_sym);
		error = EPERM;
		return (error);
	}

	error = LINKER_LOOKUP_DEBUG_SYMBOL(linker_kernel_file, func->old_sym, &sym);
	if (error != 0) {
		printf("patch: unable to find symbol %s\n", func->old_sym);
		return (error);
	}

	error = LINKER_DEBUG_SYMBOL_VALUES(linker_kernel_file, sym, &symval);
	if (error != 0) {
		printf("patch: unable to resolve symbol %s\n", func->old_sym);
		return (error);
	}

	func->old_addr = symval.value;
	func->old_size = symval.size;

	error = patch_validate_func(func);
	if (error != 0) {
		printf("patch: %s cannot be patched\n", func->old_sym);
		return (error);
	}

	return (0);
}

int
patch_load_set(patch_set_t *patch)
{
	int error;

	error = patch_iterate_set(patch, patch_resolve_func, NULL);
	if (error == 0) {
		mtx_lock(&patch_mutex);

		// Debug only
		//for (func = patch->funcs; func->old_sym != NULL; func++) {
		//	printf("patch: %s <%p>  ==>  <%p>\n",
		//		func->old_sym, func->old_addr, func->new_addr);
		//}

		struct patch_param param = {
			.patch	= patch,
			.cpuid	= curcpu,
			.op	= patch_apply_func,
			.arg	= NULL,
		};

		smp_rendezvous(NULL, patch_rendezvous_action, NULL, &param);

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
		struct patch_param param = {
			.patch	= patch,
			.cpuid	= curcpu,
			.op	= patch_rollback_func,
			.arg	= NULL,
		};

		smp_rendezvous(NULL, patch_rendezvous_action, NULL, &param);

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
