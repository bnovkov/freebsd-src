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

static volatile int	kpatch_failed_cpus;

static MALLOC_DEFINE(M_KPATCH, "kpatch", "Kernel live-patching memory");

struct resolve_ctx {
	const char *sym;
	long sympos;
	long count;
	linker_symval_t symval;
};

struct rendezvous_ctx {
	struct kpatch_set *patch;
	int cpuid;
	int (*action)(struct kpatch_func *, void *);
	void *arg;
	int error;
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

// TODO: Ideally create a linker abstract method for this
static int
kpatch_each_symbol_nameval(linker_file_t file,
    linker_function_nameval_callback_t callback, void *opaque)
{
	linker_symval_t symval;
	const Elf_Sym *symtab;
	int i, count, error;

	count = LINKER_SYMTAB_GET(file, &symtab);

	for (i = 0; i < count; i++) {
		if (symtab[i].st_value != 0) {
			error = LINKER_DEBUG_SYMBOL_VALUES(file,
					(c_linker_sym_t)&symtab[i], &symval);

			if (error == 0)
				error = callback(file, i, &symval, opaque);

			if (error != 0)
				return (error);
		}
	}
	return (0);
}

static int
kpatch_resolve(const char *sym, const char *obj, int sympos,
		linker_file_t *lf, linker_symval_t *symval)
{
	struct resolve_ctx ctx;
	linker_file_t target_lf;

	if (obj == NULL || obj[0] == 0 || !strcmp(obj, "kernel")) {
		target_lf = linker_kernel_file;
	} else {
		printf("kpatch: Unsupported target object %s\n", obj);
		return (ENOTSUP);
	}

	ctx.sym = sym;
	ctx.sympos = sympos;
	ctx.count = 0;

	kpatch_each_symbol_nameval(target_lf, kpatch_resolve_cb, &ctx);

	if (sympos < 0 && ctx.count > 1) {
		printf("kpatch: Symbol %s is ambiguous (multiple occurrences)\n", sym);
		return (EINVAL);
	}

	if (ctx.count == 0 || (sympos >= 0 && ctx.count <= sympos)) {
		printf("kpatch: Unable to resolve symbol %s\n", sym);
		return (ENOENT);
	}

	if (lf)
		*lf = target_lf;

	*symval = ctx.symval;
	return (0);
}

int
kpatch_lookup_elf(linker_file_t lf, Elf_Sym *sym, Elf_Addr *res)
{
	struct kpatch_metadata *info;
	struct kpatch_reloc_metadata *reloc;
	linker_symval_t symval;
	int error;

	info = lf->kpatch_info;
	if (info == NULL || sym->st_value >= info->relocs_count)
		return (EINVAL);

	reloc = &info->relocs[sym->st_value];
	error = kpatch_resolve(reloc->sym, reloc->obj, reloc->sympos, NULL, &symval);
	if (error != 0) {
		if (error == ENOENT && ELF_ST_BIND(sym->st_info) == STB_WEAK) {
			// Treat weak symbols as 'optional'
			symval.value = NULL;
		} else {
			return (error);
		}
	}

	/*
	 * Update the symtab to cache our custom lookup
	 * which is fairly expensive
	 */
	sym->st_value = (Elf_Addr)symval.value;
	sym->st_shndx = SHN_ABS;

	*res = (Elf_Addr)symval.value;
	return (0);
}

static int
kpatch_func_resolve(struct kpatch_func *func)
{
	linker_symval_t symval;
	int error;

	if (kpatch_func_protected(func)) {
		printf("kpatch: Patching function %s is not permitted\n", func->old_sym);
		return (EPERM);
	}

	error = kpatch_resolve(func->old_sym, func->old_obj, func->old_sympos,
			&func->old_lf, &symval);
	if (error != 0)
		return (error);

	func->old_addr = symval.value;
	func->old_size = symval.size;

	error = kpatch_func_validate(func);
	if (error != 0) {
		printf("kpatch: Function %s cannot be patched\n", func->old_sym);
		return (error);
	}

	return (0);
}

static int
kpatch_check_stack(struct stack *st, struct kpatch_set *set)
{
	struct kpatch_func *func;
	int i;

	for (i = 0; i < st->depth; i++) {
		TAILQ_FOREACH(func, &set->funcs, link) {
			if (st->pcs[i] < (vm_offset_t)func->old_addr + func->old_size
				&& st->pcs[i] >= (vm_offset_t)func->old_addr) {
				return (1);
			}
		}
	}

	return (0);
}

static int
kpatch_check_allproc(struct kpatch_set *set)
{
	struct proc *p;
	struct thread *td;
	struct stack st;
	bool sched;

	/* Fake this variable to bust lock checks */
	sched = scheduler_stopped;
	scheduler_stopped = true;

	FOREACH_PROC_IN_SYSTEM(p) {
		FOREACH_THREAD_IN_PROC(p, td) {
			/* Already checked in the rendezvous action */
			if (TD_IS_RUNNING(td))
				continue;

			stack_save_td(&st, td);
			if (kpatch_check_stack(&st, set)) {
				scheduler_stopped = sched;
				return (1);
			}
		}
	}

	scheduler_stopped = sched;
	return (0);
}

static void
kpatch_rendezvous_setup(void *arg)
{
	struct stack st;
	struct rendezvous_ctx *ctx;

	ctx = arg;

	/* First, each cpu analyzes their current stack */
	stack_zero(&st);
	stack_save(&st);

	if (kpatch_check_stack(&st, ctx->patch)) {
		atomic_add_int(&kpatch_failed_cpus, 1);
		return;
	}

	/* The master cpu checks all the stacks in allproc */
	if (curcpu == ctx->cpuid) {
		if (kpatch_check_allproc(ctx->patch)) {
			atomic_add_int(&kpatch_failed_cpus, 1);
		}
	}
}

static void
kpatch_rendezvous_action(void *arg)
{
	struct rendezvous_ctx *ctx;
	struct kpatch_func *func;

	ctx = arg;

	if (curcpu != ctx->cpuid)
		return;

	/* If any one of the checks failed, bail */
	if (kpatch_failed_cpus > 0) {
		ctx->error = EBUSY;
		return;
	}

	TAILQ_FOREACH(func, &ctx->patch->funcs, link) {
		ctx->action(func, ctx->arg);
	}
}

static void
kpatch_rendezvous_teardown(void *arg)
{
	struct rendezvous_ctx *ctx;

	ctx = arg;
	if (ctx->error != 0)
		return;

	/* Invalidate the cache after touching kernel text */
	kpatch_flush_icache();
}

static int
kpatch_rendezvous(struct kpatch_set *set, int (*action)(struct kpatch_func *, void *))
{
	struct rendezvous_ctx ctx = {
		.patch	= set,
		.cpuid	= curcpu,
		.action	= action,
		.error	= 0,
	};

	kpatch_failed_cpus = 0;
	smp_rendezvous(kpatch_rendezvous_setup, kpatch_rendezvous_action,
			kpatch_rendezvous_teardown, &ctx);
	return ctx.error;
}

static int
kpatch_func_apply(struct kpatch_func *func, void *arg __unused)
{
	if (!func->patched) {
		kpatch_install_trampoline(func);
		func->patched = true;
	}

	return (0);
}

static int
kpatch_func_rollback(struct kpatch_func *func, void *arg __unused)
{
	if (func->patched) {
		kpatch_restore_trampoline(func);
		func->patched = false;
	}

	return (0);
}

static int
kpatch_set_enable(struct kpatch_set *set)
{
	struct kpatch_func *func, *dup;
	int error, count;

	sx_assert(&kpatch_sx, SA_XLOCKED);
	sx_slock(&allproc_lock);

	if (set->enabled) {
		sx_sunlock(&allproc_lock);
		return (EALREADY);
	}

	count = 0;
	error = 0;

	TAILQ_FOREACH(func, &set->funcs, link) {
		dup = RB_INSERT(kpatch_syms, &kpatch_syms, func);
		if (dup != NULL) {
			printf("kpatch: Function %s is already patched by %s\n",
					func->old_sym, dup->patch->name);
			error = EBUSY;
			break;
		}
		count++;
	}

	if (error != 0) {
		TAILQ_FOREACH(func, &set->funcs, link) {
			if (count-- == 0)
				break;

			RB_REMOVE(kpatch_syms, &kpatch_syms, func);
		}

		sx_sunlock(&allproc_lock);
		return (error);
	}

	if (set->pre_patch != NULL) {
		error = set->pre_patch();
		if (error != 0) {
			TAILQ_FOREACH(func, &set->funcs, link) {
				RB_REMOVE(kpatch_syms, &kpatch_syms, func);
			}

			sx_sunlock(&allproc_lock);
			return (error);
		}
	}

	error = kpatch_rendezvous(set, kpatch_func_apply);
	if (error == 0) {
		set->enabled = true;
	} else {
		TAILQ_FOREACH(func, &set->funcs, link) {
			RB_REMOVE(kpatch_syms, &kpatch_syms, func);
		}
	}

	if (set->post_patch != NULL)
		set->post_patch(error);

	sx_sunlock(&allproc_lock);
	return (error);
}

static int
kpatch_set_disable(struct kpatch_set *set)
{
	struct kpatch_func *func;
	int error;

	sx_assert(&kpatch_sx, SA_XLOCKED);
	sx_slock(&allproc_lock);

	if (!set->enabled) {
		sx_sunlock(&allproc_lock);
		return (EALREADY);
	}

	if (set->pre_unpatch != NULL) {
		error = set->pre_unpatch();
		if (error != 0) {
			sx_sunlock(&allproc_lock);
			return (error);
		}
	}

	error = kpatch_rendezvous(set, kpatch_func_rollback);
	if (error == 0) {
		set->enabled = false;

		TAILQ_FOREACH(func, &set->funcs, link) {
			RB_REMOVE(kpatch_syms, &kpatch_syms, func);
		}
	}

	if (set->post_unpatch != NULL)
		set->post_unpatch(error);

	sx_sunlock(&allproc_lock);
	return (error);
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
kpatch_set_parse(struct kpatch_set_metadata *set_md)
{
	struct kpatch_func_metadata *func_md;
	struct kpatch_set *set;
	struct kpatch_func *func;
	int i;

	set = malloc(sizeof(struct kpatch_set), M_KPATCH, M_WAITOK | M_ZERO);
	set->name = set_md->name;
	set->pre_patch = set_md->pre_patch;
	set->post_patch = set_md->post_patch;
	set->pre_unpatch = set_md->pre_unpatch;
	set->post_unpatch = set_md->post_unpatch;

	sysctl_ctx_init(&set->ctx);
	TAILQ_INIT(&set->funcs);

	for (i = 0; i < set_md->funcs_count; i++) {
		func_md = &set_md->funcs[i];

		func = malloc(sizeof(struct kpatch_func), M_KPATCH, M_WAITOK | M_ZERO);
		func->patch = set;
		func->new_addr = func_md->new_addr;
		func->old_sym = func_md->old_sym;
		func->old_sympos = func_md->sympos;
		func->old_obj = func_md->old_obj;
		TAILQ_INSERT_TAIL(&set->funcs, func, link);
	}

	return (set);
}

int
kpatch_register(linker_file_t lf)
{
	struct kpatch_set **sets;
	struct kpatch_metadata *info;
	int i, j, error;

	info = lf->kpatch_info;
	if (info == NULL)
		return (0);

	sets = malloc(info->sets_count * sizeof(struct kpatch_set *),
			M_KPATCH, M_WAITOK | M_ZERO);

	for (i = 0; i < info->sets_count; i++) {
		sets[i] = kpatch_set_parse(&info->sets[i]);
		sets[i]->lf = lf;

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
	TAILQ_HEAD(, kpatch_set) tofree;

	if (lf->kpatch_info == NULL)
		return (0);

	// TODO: Maybe keep in lf the list of patchsets associated with it?

	sx_xlock(&kpatch_sx);

	TAILQ_FOREACH(set, &kpatch_list, link) {
		if (set->lf == lf && set->enabled) {
			printf("kpatch: Cannot unload %s because patch '%s' is enabled\n",
					lf->filename, set->name);
			sx_xunlock(&kpatch_sx);
			return (EBUSY);
		}
	}

	TAILQ_INIT(&tofree);

	TAILQ_FOREACH_SAFE(set, &kpatch_list, link, tmp) {
		if (set->lf != lf)
			continue;

		kpatch_set_detach(set);
		TAILQ_INSERT_TAIL(&tofree, set, link);
	}

	sx_xunlock(&kpatch_sx);

	// Clean up the memory outside of the lock
	TAILQ_FOREACH_SAFE(set, &tofree, link, tmp) {
		kpatch_set_free(set);
	}

	return (0);
}

extern char __build_id_start[];
extern char __build_id_end[];

#define	BUILD_ID_HEADER_LEN	0x10
#define	BUILD_ID_HASH_MAXLEN	0x14

/*
 * This function should be called before the load process is
 * completed so that our custom relocation logic can use the
 * metadata contained in kpatch_info->relocs
 */
int
kpatch_detect(linker_file_t lf)
{
	const uint8_t *hash;
	int hashlen, sectionlen;
	caddr_t sym_addr;
	struct kpatch_metadata *info;

	sym_addr = linker_file_lookup_symbol(lf, KPATCH_METADATA, 0);
	if (sym_addr == 0)
		return (0);

	info = (struct kpatch_metadata *)sym_addr;
	if (info->version != 0) {
		printf("kpatch: Unsupported metadata version %d\n", info->version);
		return (ENOTSUP);
	}

	if (info->build_id_len == 0) {
		printf("kpatch: Patch %s does not contain a valid build-id\n", lf->filename);
		return (ENOEXEC);
	}

	sectionlen = (int)(__build_id_end - __build_id_start);
	if (sectionlen <= BUILD_ID_HEADER_LEN ||
			sectionlen > (BUILD_ID_HEADER_LEN + BUILD_ID_HASH_MAXLEN)) {
		printf("kpatch: Running kernel has no valid build-id\n");
		return (ENOEXEC);
	}

	hashlen = sectionlen - BUILD_ID_HEADER_LEN;
	hash = (const uint8_t *)(__build_id_start + BUILD_ID_HEADER_LEN);

	if (info->build_id_len != hashlen || memcmp(info->build_id, hash, hashlen)) {
		printf("kpatch: Patch build-id does not match the running kernel\n");
		return (ENOEXEC);
	}

	lf->kpatch_info = info;
	return (0);
}

static void
kpatch_init(void *dummy __unused)
{
	TAILQ_INIT(&kpatch_list);
	RB_INIT(&kpatch_syms);
	sx_init(&kpatch_sx, "kpatch");

	printf("kpatch: Kernel live-patching available\n");
}

SYSINIT(kpatch, SI_SUB_KLD, SI_ORDER_ANY, kpatch_init, NULL);
