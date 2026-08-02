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
#include <sys/sx.h>
#include <sys/proc.h>
#include <sys/stack.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include "linker_if.h"

#define KPATCH_INTERNAL
#include <sys/kpatch.h>

static TAILQ_HEAD(, kpatch_set)			kpatch_list;
static struct mtx				kpatch_mtx;
static RB_HEAD(kpatch_syms, kpatch_func)	kpatch_syms;

static MALLOC_DEFINE(M_KPATCH, "kpatch", "Kernel live-patching memory");

static inline int
kpatch_func_cmp(struct kpatch_func *a, struct kpatch_func *b)
{
	uintptr_t addr_a = (uintptr_t)a->old_addr;
	uintptr_t addr_b = (uintptr_t)b->old_addr;

	if (addr_a < addr_b)
		return (-1);
	if (addr_a > addr_b)
		return (1);
	return (0);
}
RB_GENERATE_STATIC(kpatch_syms, kpatch_func, node, kpatch_func_cmp);

static int kpatch_set_enable(struct kpatch_set *set);
static int kpatch_set_disable(struct kpatch_set *set);

SYSCTL_NODE(_kern, OID_AUTO, patch, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Kernel live-patching");

static int
kpatch_sysctl_enable(SYSCTL_HANDLER_ARGS)
{
	struct kpatch_set *set;
	bool req_enabled;
	int error;

	set = arg1;
	req_enabled = set->enabled;

	error = sysctl_handle_bool(oidp, &req_enabled, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	if (req_enabled && !set->enabled)
		error = kpatch_set_enable(set);
	else if (!req_enabled && set->enabled)
		error = kpatch_set_disable(set);

	return (error);
}

static int
kpatch_sysctl_trampolines(SYSCTL_HANDLER_ARGS)
{
	struct sbuf sb;
	struct kpatch_func *func;
	int error;

	sbuf_new_for_sysctl(&sb, NULL, 512, req);
	sbuf_putc(&sb, '\n');

	mtx_lock(&kpatch_mtx);
	RB_FOREACH(func, kpatch_syms, &kpatch_syms) {
		sbuf_printf(&sb, " %p:\n", func->old_addr);
		sbuf_printf(&sb, "\tsymbol:\t%s\n", func->old_sym);
		sbuf_printf(&sb, "\ttarget:\t%p\n", func->new_addr);
		sbuf_printf(&sb, "\tpatch:\t%s\n", func->patch->name);
	}
	mtx_unlock(&kpatch_mtx);

	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (error);
}

SYSCTL_PROC(_kern_patch, OID_AUTO, trampolines,
	CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE,
	NULL, 0, kpatch_sysctl_trampolines, "A", "print the patched functions");

static int
kpatch_sysctl_syms(SYSCTL_HANDLER_ARGS)
{
	struct sbuf sb;
	struct kpatch_set *set;
	struct kpatch_func *func;
	int error;

	sbuf_new_for_sysctl(&sb, NULL, 512, req);
	sbuf_putc(&sb, '\n');

	mtx_lock(&kpatch_mtx);
	set = arg1;
	TAILQ_FOREACH(func, &set->funcs, link) {
		sbuf_printf(&sb, " %s\n", func->old_sym);
		sbuf_printf(&sb, "\taddr:\t%p\n", func->old_addr);
		sbuf_printf(&sb, "\ttarget:\t%p\n", func->new_addr);
		sbuf_printf(&sb, "\tpatch:\t%s\n", set->name);
		sbuf_printf(&sb, "\tinstalled:\t%s\n",
				func->patched ? "yes" : "no");
	}
	mtx_unlock(&kpatch_mtx);

	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (error);
}

static int
kpatch_sysctl_file(SYSCTL_HANDLER_ARGS)
{
	struct sbuf sb;
	struct kpatch_set *set;
	int error;

	sbuf_new_for_sysctl(&sb, NULL, 512, req);

	mtx_lock(&kpatch_mtx);
	set = arg1;
	sbuf_cat(&sb, set->lf->filename);
	mtx_unlock(&kpatch_mtx);

	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (error);
}

static int
kpatch_func_resolve(struct kpatch_func *func)
{
	return (0);
}

static int
kpatch_set_enable(struct kpatch_set *set)
{
	return (0);
}

static int
kpatch_set_disable(struct kpatch_set *set)
{
	return (0);
}

static void
kpatch_set_free(struct kpatch_set *set)
{
	struct kpatch_func *func, *tmp;

	TAILQ_FOREACH_SAFE(func, &set->funcs, link, tmp) {
		TAILQ_REMOVE(&set->funcs, func, link);
		free(func, M_KPATCH);
	}
	free(set, M_KPATCH);
}

static int
kpatch_set_attach(struct kpatch_set *set)
{
	struct kpatch_func *func;
	struct kpatch_set *set2;
	int error;

	TAILQ_FOREACH(func, &set->funcs, link) {
		func->patch = set;

		error = kpatch_func_resolve(func);
		if (error != 0)
			return (error);
	}

	mtx_lock(&kpatch_mtx);

	TAILQ_FOREACH(set2, &kpatch_list, link) {
		if (!strcmp(set2->name, set->name)) {
			printf("kpatch: Duplicate patch name '%s'\n", set->name);
			mtx_unlock(&kpatch_mtx);
			return (EEXIST);
		}
	}

	TAILQ_INSERT_TAIL(&kpatch_list, set, link);
	mtx_unlock(&kpatch_mtx);

	// Add sysctl nodes
	sysctl_ctx_init(&set->ctx);

	set->oidp = SYSCTL_ADD_NODE(&set->ctx,
			SYSCTL_STATIC_CHILDREN(_kern_patch), OID_AUTO,
			set->name, CTLFLAG_RW | CTLFLAG_MPSAFE,
			0, "patch module");

	SYSCTL_ADD_PROC(&set->ctx, SYSCTL_CHILDREN(set->oidp), OID_AUTO,
			"enable", CTLTYPE_U8 | CTLFLAG_RW | CTLFLAG_MPSAFE,
			set, 0, kpatch_sysctl_enable, "CU", "toggle patch");

	SYSCTL_ADD_PROC(&set->ctx, SYSCTL_CHILDREN(set->oidp), OID_AUTO,
			"syms", CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE,
			set, 0, kpatch_sysctl_syms, "A", "targeted symbols");

	SYSCTL_ADD_PROC(&set->ctx, SYSCTL_CHILDREN(set->oidp), OID_AUTO,
			"file", CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE,
			set, 0, kpatch_sysctl_file, "A", "linker file");

	set->attached = true;
	return (error);
}

static int
kpatch_set_detach(struct kpatch_set *set)
{
	int error;

	mtx_lock(&kpatch_mtx);
	if (set->enabled) {
		mtx_unlock(&kpatch_mtx);
		return (EBUSY);
	}


	// Mark as detached in advance to avoid races
	set->attached = false;
	mtx_unlock(&kpatch_mtx);
	

	error = sysctl_ctx_free(&set->ctx);
	if (error != 0) {
		mtx_lock(&kpatch_mtx);
		set->attached = true;
		mtx_unlock(&kpatch_mtx);
		return (error);
	}

	mtx_lock(&kpatch_mtx);
	TAILQ_REMOVE(&kpatch_list, set, link);
	mtx_unlock(&kpatch_mtx);

	return (0);
}

static struct kpatch_set *
kpatch_set_parse(struct kpatch_set_metadata *patch)
{
	struct kpatch_set *set;
	struct kpatch_func *func;
	int i;

	set = malloc(sizeof(struct kpatch_set), M_KPATCH, M_WAITOK | M_ZERO);
	set->name = patch->name;
	TAILQ_INIT(&set->funcs);

	for (i = 0; i < patch->count; i++) {
		func = malloc(sizeof(struct kpatch_func), M_KPATCH, M_WAITOK | M_ZERO);
		func->patch = set;
		func->new_addr = patch->funcs[i].new_addr;
		func->old_sym = patch->funcs[i].old_sym;
		// TODO: Resolve linker file from objname
		// func->old_lf = patch->old_obj;
		func->old_sympos = patch->funcs[i].sympos;
		TAILQ_INSERT_TAIL(&set->funcs, func, link);
	}

	return (set);
}

int
kpatch_register(linker_file_t lf, struct kpatch_set_metadata **patches, int count)
{
	struct kpatch_set **sets;
	int i, j, error;

	sets = malloc(count * sizeof(struct kpatch_set *), M_KPATCH, M_WAITOK | M_ZERO);

	for (i = 0; i < count; i++) {
		sets[i] = kpatch_set_parse(patches[i]);
		sets[i]->lf = lf;
		error = kpatch_set_attach(sets[i]);
		if (error == 0)
			continue;

		// Rollback all the sets and cleanup
		for (j = 0; j < i; j++) {
			kpatch_set_detach(sets[j]);
			kpatch_set_free(sets[j]);
		}

		kpatch_set_free(sets[i]);
		break;
	}

	free(sets, M_KPATCH);
	return (error);
}

int
kpatch_unregister(linker_file_t lf, int flags)
{
	struct kpatch_set *patch, *tmp;
	int error;

	mtx_lock(&kpatch_mtx);
	TAILQ_FOREACH(patch, &kpatch_list, link) {
		if (patch->lf == lf && patch->enabled) {
			printf("kpatch: Cannot unload %s because patch '%s' is enabled\n",
					patch->name, lf->filename);
			mtx_unlock(&kpatch_mtx);
			return (EBUSY);
		}
	}
	mtx_unlock(&kpatch_mtx);

	// Actually clean up the memory
	TAILQ_FOREACH_SAFE(patch, &kpatch_list, link, tmp) {
		if (patch->lf != lf)
			continue;

		error = kpatch_set_detach(patch);
		if (error != 0)
			return (error);

		kpatch_set_free(patch);
	}

	return (0);
}

static void
kpatch_init(void *dummy __unused)
{
	TAILQ_INIT(&kpatch_list);
	RB_INIT(&kpatch_syms);
	mtx_init(&kpatch_mtx, "kpatch", NULL, MTX_DEF);

	printf("kpatch: Kernel patching available\n");
}

SYSINIT(kpatch, SI_SUB_KLD, SI_ORDER_ANY, kpatch_init, NULL);
