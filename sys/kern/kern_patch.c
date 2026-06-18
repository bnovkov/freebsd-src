#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/cdefs.h>
#include <sys/kernel.h>
#include <sys/patch.h>
#include <sys/mutex.h>
#include <sys/linker.h>
#include <sys/smp.h>

#include "linker_if.h"

struct patch_param {
	patch_set_t *patch;
	int cpuid;
	int (*action)(patch_func_t *, void *);
	void *arg;
};

static TAILQ_HEAD(, patch_set)		patch_list;
static struct mtx			patch_mutex;
static RB_HEAD(patch_syms, patch_func)	patch_syms;

static inline int
patch_func_cmp(patch_func_t *a, patch_func_t *b)
{
	uintptr_t addr_a = (uintptr_t)a->old_addr;
	uintptr_t addr_b = (uintptr_t)b->old_addr;

	if (addr_a < addr_b)
		return (-1);
	if (addr_a > addr_b)
		return (1);
	return (0);
}

RB_GENERATE_STATIC(patch_syms, patch_func, node, patch_func_cmp);

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

static void
patch_rendezvous_action(void *arg)
{
	struct patch_param *param;
	patch_func_t *func;

	param = (struct patch_param *)arg;
	if (curcpu == param->cpuid) {
		PATCH_FOREACH(param->patch, func) {
			param->action(func, param->arg);
		}
	}

	// TODO: Flush icache here
}

static int
patch_resolve_func(patch_func_t *func)
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

static int
patch_apply_func(patch_func_t *func, void *arg __unused)
{
	if (!func->patched) {
		patch_install_trampoline(func);
		func->patched = true;
	}

	return (0);
}

static int
patch_rollback_func(patch_func_t *func, void *arg __unused)
{
	if (func->patched) {
		patch_restore_trampoline(func);
		func->patched = false;
	}

	return (0);
}

int
patch_register(patch_set_t *patch)
{
	patch_func_t *func;
	int error;

	PATCH_FOREACH(patch, func) {
		error = patch_resolve_func(func);
		if (error != 0)
			return (error);
	}

	mtx_lock(&patch_mutex);
	TAILQ_INSERT_TAIL(&patch_list, patch, link);
	mtx_unlock(&patch_mutex);

	return (error);
}

int
patch_unregister(patch_set_t *patch)
{
	int error;

	mtx_lock(&patch_mutex);
	if (patch->enabled) {
		error = EBUSY;
	} else {
		error = 0;
		TAILQ_REMOVE(&patch_list, patch, link);
	}

	mtx_unlock(&patch_mutex);
	return (error);
}

int
patch_enable(patch_set_t *patch)
{
	patch_func_t *func, *dup;
	int error, count;

	mtx_lock(&patch_mutex);

	if (patch->enabled) {
		mtx_unlock(&patch_mutex);
		return (EALREADY);
	}

	count = 0;
	error = 0;

	PATCH_FOREACH(patch, func) {
		dup = RB_INSERT(patch_syms, &patch_syms, func);
		if (dup != NULL) {
		    printf("patch: %s is already patched\n", func->old_sym);
		    error = EBUSY;
		    break;
		}
		count++;
	}

	if (error != 0) {
		PATCH_FOREACH(patch, func) {
			if (count-- == 0)
				break;

			RB_REMOVE(patch_syms, &patch_syms, func);
		}

		mtx_unlock(&patch_mutex);
		return (error);
	}

	struct patch_param param = {
		.patch	= patch,
		.cpuid	= curcpu,
		.action	= patch_apply_func,
		.arg	= NULL,
	};

	smp_rendezvous(NULL, patch_rendezvous_action, NULL, &param);

	patch->enabled = true;

	mtx_unlock(&patch_mutex);
	return (error);
}

int
patch_disable(patch_set_t *patch)
{
	patch_func_t *func;

	mtx_lock(&patch_mutex);

	if (patch->enabled) {
		struct patch_param param = {
			.patch	= patch,
			.cpuid	= curcpu,
			.action	= patch_rollback_func,
			.arg	= NULL,
		};

		smp_rendezvous(NULL, patch_rendezvous_action, NULL, &param);

		PATCH_FOREACH(patch, func) {
			RB_REMOVE(patch_syms, &patch_syms, func);
		}

		patch->enabled = false;
	}

	mtx_unlock(&patch_mutex);
	return (0);
}

static void
patch_init(void *dummy __unused)
{
	TAILQ_INIT(&patch_list);
	RB_INIT(&patch_syms);
	mtx_init(&patch_mutex, "patch", NULL, MTX_DEF);

	printf("patch: kernel patching available\n");
}

SYSINIT(patch, SI_SUB_KLD, SI_ORDER_ANY, patch_init, NULL);
