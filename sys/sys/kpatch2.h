#ifndef _SYS_KPATCH_H_
#define	_SYS_KPATCH_H_

#include <sys/types.h>

struct kpatch_set_metadata {
	const char *name;
	int flags;
	int funcs_count;
	struct kpatch_func_metadata *funcs;
};

struct kpatch_func_metadata {
	void *new_addr;
	const char *old_sym;
	const char *old_obj;
	int sympos;
	int flags;
};

#define KPATCH_SETNAME		"kpatch_set"

/*
 * Internal API of the subsystem, exclusively for kernel use.
 */
#ifdef KPATCH_INTERNAL

#include <sys/module.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/linker.h>
#include <sys/linker_set.h>
#include <machine/kpatch.h>

/*
 * Represent a whole patch, and contains metadata and a list of funcs
 */
typedef struct kpatch_set {
	const char *name;
	TAILQ_HEAD(, patch_func) funcs;

	/* private fields */
	bool enabled;
	linker_file_t lf;
	module_t mod;
	TAILQ_ENTRY(patch_set) link;

	struct sysctl_ctx_list ctx;
	struct sysctl_oid *oidp;
} kpatch_set_t;

/*
 * Contains information about a single patched symbol
 */
typedef struct kpatch_func {
	TAILQ_ENTRY(kpatch_func) link;
	const char *old_sym;
	unsigned old_sympos;
	void *new_addr;

	/* private fields */
	bool patched;
	void *old_addr;
	size_t old_size;
	linker_file_t old_lf;
	uint8_t old_text[PATCH_TEXTLEN];
	RB_ENTRY(patch_func) node;
	struct patch_set *patch;
} kpatch_func_t;

#define PATCH_FOREACH(patch, var)		\
	for ((var) = (patch)->funcs;		\
	    (var)->old_sym != NULL;		\
	    (var)++)

int patch_register_file(linker_file_t lf,
	struct kpatch_metadata **patches, int pcount,
	struct kpatch_func_metadata **funcs, int fcount);

int patch_unregister_file(linker_file_t lf, int flags);

int patch_excluded(const char *name);

int patch_enable(patch_set_t *patch);

int patch_disable(patch_set_t *patch);

/*
 * Machine dependant functions
 */
int patch_validate_func(patch_func_t *func);

void patch_install_trampoline(patch_func_t *func);

void patch_restore_trampoline(patch_func_t *func);

#endif /* KPATCH_INTERNAL */

#endif
