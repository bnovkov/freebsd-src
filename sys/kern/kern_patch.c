#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/cdefs.h>
#include <sys/kernel.h>
#include <sys/mutex.h>
#include <sys/linker.h>
#include <sys/smp.h>
#include <sys/sbuf.h>
#include <sys/malloc.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include "linker_if.h"

#define KPATCH_INTERNAL
#include <sys/kpatch.h>

struct patch_param {
	patch_set_t *patch;
	int cpuid;
	int (*action)(patch_func_t *, void *);
	void *arg;
};

struct patch_resolve {
	const char *sym;
	long sympos;
	long count;
	linker_symval_t symval;
};

static TAILQ_HEAD(, patch_set)		patch_list;
static struct mtx			patch_mutex;
static RB_HEAD(patch_syms, patch_func)	patch_syms;

static MALLOC_DEFINE(M_KPATCH, "kpatch", "Kernel live-patching memory");

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
}

static void
patch_rendezvous_teardown(void *arg __unused)
{
	pmap_invalidate_cache();
}

static int
patch_resolve_sym(linker_file_t lf, int symnum, linker_symval_t *symval, void *arg)
{
	struct patch_resolve *ctx;

	ctx = arg;
	if (strcmp(symval->name, ctx->sym))
		return (0);

	ctx->count++;

	if (ctx->sympos > 0 && ctx->sympos == ctx->count) {
		ctx->symval = *symval;
		return (1);
	}

	/*
	 * The idea here is that if we have sympos 0 we do not want
	 * actually the first occurrence but want the 'automatic' symbol.
	 * Meaning that if we have even two symbol with the same name we bail.
	 * The same could be accomplished by incrementing match count later and
	 * using maybe a negative number as sentinel.
	 */
	if (ctx->sympos == 0) {
		if (ctx->count == 1)
			ctx->symval = *symval;
		else
			return (1);
	}

	return (0);
}

static int
patch_resolve_func(patch_func_t *func)
{
	struct patch_resolve ctx;
	int error;

	if (patch_excluded(func->old_sym)) {
		printf("patch: symbol %s is protected\n", func->old_sym);
		return (EPERM);
	}

	ctx.sym = func->old_sym;
	ctx.sympos = func->old_sympos;
	ctx.count = 0;

	LINKER_EACH_FUNCTION_NAMEVAL(func->old_lf, patch_resolve_sym, &ctx);

	if (func->old_sympos == 0 && ctx.count > 1) {
		printf("patch: symbol %s is ambiguous (more than 1 occurrences)\n", func->old_sym);
		return (EINVAL);
	}

	if (ctx.count == 0 || (func->old_sympos > 0 && ctx.count < func->old_sympos)) {
		printf("patch: unable to resolve symbol %s\n", func->old_sym);
		return (ENOENT);
	}

	func->old_addr = ctx.symval.value;
	func->old_size = ctx.symval.size;

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

	smp_rendezvous(NULL, patch_rendezvous_action, patch_rendezvous_teardown, &param);

	patch->enabled = true;

	mtx_unlock(&patch_mutex);
	return (error);
}

static int
patch_disable_unlocked(patch_set_t *patch)
{
	patch_func_t *func;

	if (!patch->enabled)
		return (0);

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
	return (0);
}

int
patch_disable(patch_set_t *patch)
{
	int error;

	mtx_lock(&patch_mutex);
	error = patch_disable_unlocked(patch);
	mtx_unlock(&patch_mutex);

	return (error);
}

SYSCTL_NODE(_kern, OID_AUTO, patch, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Kernel live-patching");

static int
patch_sysctl_enable(SYSCTL_HANDLER_ARGS)
{
	patch_set_t *patch = arg1;
	bool req_enabled = patch->enabled;
	int error;

	error = sysctl_handle_bool(oidp, &req_enabled, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	if (req_enabled && !patch->enabled)
		error = patch_enable(patch);
	else if (!req_enabled && patch->enabled)
		error = patch_disable(patch);

	return (error);
}

static int
patch_sysctl_trampolines(SYSCTL_HANDLER_ARGS)
{
	struct sbuf sb;
	patch_func_t *func;
	int error;

	sbuf_new_for_sysctl(&sb, NULL, 512, req);
	sbuf_putc(&sb, '\n');

	mtx_lock(&patch_mutex);
	RB_FOREACH(func, patch_syms, &patch_syms) {
		sbuf_printf(&sb, " %p:\n", func->old_addr);
		sbuf_printf(&sb, "\tsymbol:\t%s\n", func->old_sym);
		sbuf_printf(&sb, "\ttarget:\t%p\n", func->new_addr);
		sbuf_printf(&sb, "\tpatch:\t%s\n", func->patch->name);
	}
	mtx_unlock(&patch_mutex);

	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (error);
}

SYSCTL_PROC(_kern_patch, OID_AUTO, trampolines,
	CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE,
	NULL, 0, patch_sysctl_trampolines, "A", "print the patched functions");

static int
patch_sysctl_syms(SYSCTL_HANDLER_ARGS)
{
	struct sbuf sb;
	patch_set_t *patch;
	patch_func_t *func;
	int error;

	sbuf_new_for_sysctl(&sb, NULL, 512, req);
	sbuf_putc(&sb, '\n');

	mtx_lock(&patch_mutex);
	patch = arg1;
	PATCH_FOREACH(patch, func) {
		sbuf_printf(&sb, " %s\n", func->old_sym);
		sbuf_printf(&sb, "\taddr:\t%p\n", func->old_addr);
		sbuf_printf(&sb, "\ttarget:\t%p\n", func->new_addr);
		sbuf_printf(&sb, "\tpatch:\t%s\n", func->patch->name);
		sbuf_printf(&sb, "\tinstalled:\t%s\n",
				func->patched ? "yes" : "no");
	}
	mtx_unlock(&patch_mutex);

	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (error);
}

static int
patch_sysctl_file(SYSCTL_HANDLER_ARGS)
{
	struct sbuf sb;
	patch_set_t *patch;
	int error;

	sbuf_new_for_sysctl(&sb, NULL, 512, req);

	mtx_lock(&patch_mutex);
	patch = arg1;
	sbuf_cat(&sb, patch->lf->filename);
	mtx_unlock(&patch_mutex);

	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (error);
}

static int
patch_register(patch_set_t *patch)
{
	patch_func_t *func;
	patch_set_t *other;
	int error;

	PATCH_FOREACH(patch, func) {
		func->patch = patch;

		error = patch_resolve_func(func);
		if (error != 0)
			return (error);
	}

	mtx_lock(&patch_mutex);

	TAILQ_FOREACH(other, &patch_list, link) {
		if (!strcmp(other->name, patch->name)) {
			printf("patch: Already registered patch named '%s'\n", patch->name);
			mtx_unlock(&patch_mutex);
			return (EEXIST);
		}
	}

	TAILQ_INSERT_TAIL(&patch_list, patch, link);
	mtx_unlock(&patch_mutex);

	// Add sysctl nodes
	sysctl_ctx_init(&patch->ctx);

	patch->oidp = SYSCTL_ADD_NODE(&patch->ctx,
			SYSCTL_STATIC_CHILDREN(_kern_patch), OID_AUTO,
			patch->name, CTLFLAG_RW | CTLFLAG_MPSAFE,
			0, "patch module");

	SYSCTL_ADD_PROC(&patch->ctx, SYSCTL_CHILDREN(patch->oidp), OID_AUTO,
			"enable", CTLTYPE_U8 | CTLFLAG_RW | CTLFLAG_MPSAFE,
			patch, 0, patch_sysctl_enable, "CU", "toggle patch");

	SYSCTL_ADD_PROC(&patch->ctx, SYSCTL_CHILDREN(patch->oidp), OID_AUTO,
			"syms", CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE,
			patch, 0, patch_sysctl_syms, "A", "targeted symbols");

	SYSCTL_ADD_PROC(&patch->ctx, SYSCTL_CHILDREN(patch->oidp), OID_AUTO,
			"file", CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE,
			patch, 0, patch_sysctl_file, "A", "linker file");

	return (error);
}

static int
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

	if (error == 0) {
		sysctl_ctx_free(&patch->ctx);
	}
	return (error);
}

int
patch_register_file(linker_file_t lf, struct kpatch_metadata **patches, int pcount,
                       struct kpatch_func_metadata **funcs, int fcount)
{
	patch_set_t **sets;
	patch_func_t *func;
	int *func_counts;
	int error, i, j;

	sets = malloc(pcount * sizeof(patch_set_t *), M_KPATCH, M_WAITOK | M_ZERO);
	func_counts = malloc(pcount * sizeof(int), M_KPATCH, M_WAITOK | M_ZERO);

	// Init patch sets
	for (i = 0; i < pcount; i++) {
		sets[i] = malloc(sizeof(patch_set_t), M_KPATCH, M_WAITOK | M_ZERO);
		sets[i]->name = patches[i]->name;
		sets[i]->lf = lf;
		sets[i]->funcs = malloc(sizeof(patch_func_t), M_KPATCH, M_WAITOK | M_ZERO);
	}

	// Appending the functions
	error = 0;
	for (j = 0; j < fcount; j++) {
		for (i = 0; i < pcount; i++) {
			if (!strcmp(funcs[j]->patch, sets[i]->name))
				break;
		}

		if (i < pcount) {
			sets[i]->funcs = realloc(sets[i]->funcs ,
						sizeof(patch_func_t) * (func_counts[i] + 2),
						M_KPATCH, M_WAITOK);

			func = &sets[i]->funcs[func_counts[i]++];
			func->patch = sets[i];
			func->old_sym = funcs[j]->old_sym;
			func->new_addr = funcs[j]->new_addr;

			if (funcs[j]->flags & PATCH_FUNC_SYMPOS)
				func->old_sympos = funcs[j]->uniquifier.sympos;
			else
				func->old_sympos = 0;

			if (funcs[j]->old_obj == NULL || !strcmp(funcs[j]->old_obj, "kernel")) {
				func->old_lf = linker_kernel_file;
			} else {
				// TODO: When dealing with modules we need to handle refcount and locking
				printf("patch: Cannot patch object other than 'kernel'\n");
				error = EINVAL;
				goto cleanup;
			}

			bzero(&sets[i]->funcs[func_counts[i]], sizeof(patch_func_t));
		} else {
			printf("patch: Function '%s' references unknown patch set '%s'\n",
					funcs[j]->old_sym, funcs[j]->patch);
			error = ENOENT;
			goto cleanup;
		}
	}

	// Register the new funcs
	for (i = 0; i < pcount; i++) {
		error = patch_register(sets[i]);
		if (error != 0) {
			// Unregister everything else
			for (j = 0; j < i; j++) {
				patch_unregister(sets[j]);
			}
			goto cleanup;
		}
	}

cleanup:
	if (error != 0) {
		for (i = 0; i < pcount; i++) {
			free(sets[i]->funcs, M_KPATCH);
			free(sets[i], M_KPATCH);
		}
	}

	free(func_counts, M_KPATCH);
	free(sets, M_KPATCH);
	return (error);
}

int
patch_unregister_file(linker_file_t lf, int flags)
{
	patch_set_t *patch, *tmp;

	mtx_lock(&patch_mutex);
	TAILQ_FOREACH(patch, &patch_list, link) {
		if (patch->lf == lf && patch->enabled) {
//			if (flags != LINKER_UNLOAD_FORCE) {
				printf("patch: Cannot unload %s because patch '%s' is enabled\n",
						patch->name, lf->filename);
				mtx_unlock(&patch_mutex);
				return (EBUSY);
//			}

//			// XXX: Should a force unload disable the patch?
//			patch_disable_unlocked(patch);
//			printf("patch: Disabled patch '%s' because %s is being unloaded\n",
//					lf->filename, patch->name);
		}
	}
	mtx_unlock(&patch_mutex);

	// Actually clean up the memory
	TAILQ_FOREACH_SAFE(patch, &patch_list, link, tmp) {
		if (patch->lf != lf)
			continue;

		patch_unregister(patch);
		free(patch->funcs, M_KPATCH);
		free(patch, M_KPATCH);
	}

	return (0);
}

static void
patch_init(void *dummy __unused)
{
	TAILQ_INIT(&patch_list);
	RB_INIT(&patch_syms);
	mtx_init(&patch_mutex, "patch", NULL, MTX_DEF);

	printf("patch: Kernel patching available\n");
}

SYSINIT(patch, SI_SUB_KLD, SI_ORDER_ANY, patch_init, NULL);
