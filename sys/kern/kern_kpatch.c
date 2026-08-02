#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/cdefs.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/smp.h>
#include <sys/sbuf.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/proc.h>
#include <sys/stack.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include "linker_if.h"

#define KPATCH_INTERNAL
#include <sys/kpatch.h>

static TAILQ_HEAD(, kpatch_set)			kpatch_list;
static struct sx				kpatch_sx;
static RB_HEAD(kpatch_syms, kpatch_func)	kpatch_syms;

static MALLOC_DEFINE(M_KPATCH, "kpatch", "Kernel live-patching memory");

struct resolve_ctx {
	const char *sym;
	long sympos;
	long count;
	linker_symval_t symval;
};

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

	sx_xlock(&kpatch_sx);
	if (!set->attached) {
		sx_xunlock(&kpatch_sx);
		return (EBUSY);
	}

	if (req_enabled && !set->enabled) {
		error = kpatch_set_enable(set);
	} else if (!req_enabled && set->enabled) {
		error = kpatch_set_disable(set);
	}

	sx_xunlock(&kpatch_sx);
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

	sx_slock(&kpatch_sx);
	RB_FOREACH(func, kpatch_syms, &kpatch_syms) {
		sbuf_printf(&sb, " %p:\n", func->old_addr);
		sbuf_printf(&sb, "\tsymbol:\t%s\n", func->old_sym);
		sbuf_printf(&sb, "\ttarget:\t%p\n", func->new_addr);
		sbuf_printf(&sb, "\tpatch:\t%s\n", func->patch->name);
	}
	sx_sunlock(&kpatch_sx);

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

	sx_slock(&kpatch_sx);
	set = arg1;
	TAILQ_FOREACH(func, &set->funcs, link) {
		sbuf_printf(&sb, " %s\n", func->old_sym);
		sbuf_printf(&sb, "\taddr:\t%p\n", func->old_addr);
		sbuf_printf(&sb, "\ttarget:\t%p\n", func->new_addr);
		sbuf_printf(&sb, "\tpatch:\t%s\n", set->name);
		sbuf_printf(&sb, "\tinstalled:\t%s\n",
				func->patched ? "yes" : "no");
	}
	sx_sunlock(&kpatch_sx);

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

	sx_slock(&kpatch_sx);
	set = arg1;
	sbuf_cat(&sb, set->lf->filename);
	sx_sunlock(&kpatch_sx);

	error = sbuf_finish(&sb);
	sbuf_delete(&sb);
	return (error);
}

static int
kpatch_func_protected(const struct kpatch_func *func)
{
	if (!strncmp(func->old_sym, "kpatch_", 7))
		return (1);

	return (0);
}

static int
kpatch_resolve_cb(linker_file_t lf, int symnum, linker_symval_t *symval, void *arg)
{
	struct resolve_ctx *ctx;

	ctx = arg;
	if (strcmp(symval->name, ctx->sym))
		return (0);

	if (ctx->sympos == ctx->count++ && ctx->sympos >= 0) {
		ctx->symval = *symval;
		return (1);
	}

	/*
	 * The idea here is that if we have a negative sympos we want the
	 * 'automatic' symbol. Meaning that if we have even two symbol with
	 * the same name we bail.
	 */
	if (ctx->sympos < 0) {
		if (ctx->count == 1)
			ctx->symval = *symval;
		else
			return (1);
	}

	return (0);
}

static int
kpatch_func_resolve(struct kpatch_func *func)
{
	struct resolve_ctx ctx;
	int error;

	if (kpatch_func_protected(func)) {
		printf("kpatch: Function %s is protected\n", func->old_sym);
		return (EPERM);
	}

	if (func->old_obj == NULL || !strcmp(func->old_obj, "kernel")) {
		func->old_lf = linker_kernel_file;
	} else {
		printf("kpatch: Unsupported target object %s\n", func->old_obj);
		return (ENOTSUP);
	}

	ctx.sym = func->old_sym;
	ctx.sympos = func->old_sympos;
	ctx.count = 0;

	LINKER_EACH_FUNCTION_NAMEVAL(func->old_lf, kpatch_resolve_cb, &ctx);

	if (func->old_sympos < 0 && ctx.count > 1) {
		printf("kpatch: Symbol %s is ambiguous (multiple occurrences)\n", func->old_sym);
		return (EINVAL);
	}

	if (ctx.count == 0 || (func->old_sympos >= 0 && ctx.count <= func->old_sympos)) {
		printf("kpatch: Unable to resolve symbol %s\n", func->old_sym);
		return (ENOENT);
	}

	func->old_addr = ctx.symval.value;
	func->old_size = ctx.symval.size;

	error = kpatch_func_validate(func);
	if (error != 0) {
		printf("kpatch: Function %s cannot be patched\n", func->old_sym);
		return (error);
	}

	return (0);
}

static int
kpatch_set_enable(struct kpatch_set *set)
{
	sx_assert(&kpatch_sx, SA_XLOCKED);
	return (0);
}

static int
kpatch_set_disable(struct kpatch_set *set)
{
	sx_assert(&kpatch_sx, SA_XLOCKED);
	return (0);
}

static void
kpatch_set_free(struct kpatch_set *set)
{
	struct kpatch_func *func, *tmp;

	sx_assert(&kpatch_sx, SA_UNLOCKED);
	sysctl_ctx_free(&set->ctx);

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

	sx_xlock(&kpatch_sx);
	TAILQ_FOREACH(set2, &kpatch_list, link) {
		if (!strcmp(set2->name, set->name)) {
			printf("kpatch: Duplicate patch name '%s'\n", set->name);
			sx_xunlock(&kpatch_sx);
			return (EEXIST);
		}
	}

	TAILQ_INSERT_TAIL(&kpatch_list, set, link);
	sx_xunlock(&kpatch_sx);

	// Add sysctl nodes
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

static void
kpatch_set_detach(struct kpatch_set *set)
{
	sx_assert(&kpatch_sx, SA_XLOCKED);

	TAILQ_REMOVE(&kpatch_list, set, link);
	set->attached = false;
}

static struct kpatch_set *
kpatch_set_parse(struct kpatch_set_metadata *metadata, linker_file_t lf)
{
	struct kpatch_set *set;
	struct kpatch_func *func;
	int i;

	set = malloc(sizeof(struct kpatch_set), M_KPATCH, M_WAITOK | M_ZERO);
	set->name = metadata->name;
	set->lf = lf;

	sysctl_ctx_init(&set->ctx);
	TAILQ_INIT(&set->funcs);

	for (i = 0; i < metadata->count; i++) {
		func = malloc(sizeof(struct kpatch_func), M_KPATCH, M_WAITOK | M_ZERO);
		func->patch = set;
		func->new_addr = metadata->funcs[i].new_addr;
		func->old_sym = metadata->funcs[i].old_sym;
		func->old_sympos = metadata->funcs[i].sympos;
		func->old_obj = metadata->funcs[i].old_obj;
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
		sets[i] = kpatch_set_parse(patches[i], lf);
		error = kpatch_set_attach(sets[i]);
		if (error == 0)
			continue;

		// Rollback all the sets and cleanup
		sx_xlock(&kpatch_sx);
		for (j = 0; j < i; j++) {
			kpatch_set_detach(sets[j]);
		}
		sx_xunlock(&kpatch_sx);

		for (j = 0; j <= i; j++) {
			kpatch_set_free(sets[j]);
		}
		break;
	}

	free(sets, M_KPATCH);
	return (error);
}

int
kpatch_unregister(linker_file_t lf, int flags)
{
	struct kpatch_set *set, *tmp;
	TAILQ_HEAD(, kpatch_set) dead_list;

	sx_xlock(&kpatch_sx);

	TAILQ_FOREACH(set, &kpatch_list, link) {
		if (set->lf == lf && set->enabled) {
			printf("kpatch: Cannot unload %s because patch '%s' is enabled\n",
					set->name, lf->filename);
			sx_xunlock(&kpatch_sx);
			return (EBUSY);
		}
	}

	TAILQ_INIT(&dead_list);

	TAILQ_FOREACH_SAFE(set, &kpatch_list, link, tmp) {
		if (set->lf != lf)
			continue;

		kpatch_set_detach(set);
		TAILQ_INSERT_TAIL(&dead_list, set, link);
	}

	sx_xunlock(&kpatch_sx);

	TAILQ_FOREACH_SAFE(set, &dead_list, link, tmp) {
		// Actually clean up the memory
		kpatch_set_free(set);
	}

	return (0);
}

static void
kpatch_init(void *dummy __unused)
{
	TAILQ_INIT(&kpatch_list);
	RB_INIT(&kpatch_syms);
	sx_init(&kpatch_sx, "kpatch");

	printf("kpatch: Kernel patching available\n");
}

SYSINIT(kpatch, SI_SUB_KLD, SI_ORDER_ANY, kpatch_init, NULL);
