#ifndef _SYS_KPATCH_H_
#define	_SYS_KPATCH_H_

#include <sys/types.h>

/*
 * This is the public interface that kernel modules
 * and the post-processing tools are allowed to use
 */

#define PATCH_FUNC_SYMPOS 0x1

struct kpatch_metadata {
	const char *name;
	const char *desc;
	long flags;
};

struct kpatch_func_metadata {
	const char *patch;
	const char *new_sym;
	void *new_addr;
	const char *old_sym;
	const char *old_obj;
	union {
		const char *old_file;
		long sympos;
	} uniquifier;
	long flags;
};

struct kpatch_reloc_metadata {
	const char *local_sym;
	const char *real_sym;
	const char *real_obj;
	const char *real_file;
	long flags;
};

#define PATCH_SETNAME		"kpatch_set"
#define PATCH_FUNC_SETNAME	"kpatch_func_set"

#ifdef _KERNEL

#include <sys/cdefs.h>

#define PATCH_CONCAT(name, uniquifier)	__kpatch_##name##_##uniquifier

/*
#define PATCH_DECLARE(name, desc, flags) \
	 __used __section(".kpatch.sets") \
	static struct kpatch_metadata PATCH_CONCAT(name, info) = { \
		#name, desc, flags \
	};

#define PATCH_FUNC_FULL(patch, new_sym, old_sym, old_obj, uniquifier, flags) \
	 __used __section(".kpatch.funcs.pre") \
	static struct kpatch_func_metadata PATCH_CONCAT(patch, func__##new_sym) = { \
		#patch, #new_sym, new_sym, old_sym, old_obj, { uniquifier }, flags \
	};

#define PATCH_FUNC(patch, new_sym, old_sym, old_obj, old_file) \
	PATCH_FUNC_FULL(patch, new_sym, old_sym, old_obj, old_file, 0)

#define PATCH_RELOC(local, sym, obj, file) \
	__used __section(".kpatch.relocs") \
	static struct kpatch_reloc_metadata PATCH_CONCAT(, reloc__##local) = { \
		#local, sym, obj, file, 0 \
	};
*/

#define PATCH_DECLARE(name, desc, flags) \
	static struct kpatch_metadata PATCH_CONCAT(name, info) = { \
		#name, desc, flags \
	}; \
	DATA_SET(kpatch_set, PATCH_CONCAT(name, info))

#define PATCH_FUNC_FULL(patch, new_sym, old_sym, old_obj, uniquifier, flags) \
	static struct kpatch_func_metadata PATCH_CONCAT(patch, func__##new_sym) = { \
		#patch, #new_sym, new_sym, old_sym, old_obj, { uniquifier }, flags \
	}; \
	DATA_SET(kpatch_func_set, PATCH_CONCAT(patch, func__##new_sym))

#define PATCH_FUNC(patch, new_sym, old_sym, old_obj, old_file) \
	PATCH_FUNC_FULL(patch, new_sym, old_sym, old_obj, old_file, 0)

#define PATCH_RELOC(local, sym, obj, file) // not implemented yet

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
typedef struct patch_set {
	const char *name;
	struct patch_func *funcs;

	/* private fields */
	bool enabled;
	linker_file_t lf;
	module_t mod;
	TAILQ_ENTRY(patch_set) link;

	struct sysctl_ctx_list ctx;
	struct sysctl_oid *oidp;
} patch_set_t;

/*
 * Contains information about a single patched symbol
 */
typedef struct patch_func {
	const char *old_sym;
	unsigned old_sympos;
	void *new_addr;

	/* private fields */
	bool patched;
	void *old_addr;
	size_t old_size;
//	linker_file_t lf;
	uint8_t old_text[PATCH_TEXTLEN];
	RB_ENTRY(patch_func) node;
	struct patch_set *patch;
} patch_func_t;

#define PATCH_FOREACH(patch, var)		\
	for ((var) = (patch)->funcs;		\
	    (var)->old_sym != NULL;		\
	    (var)++)

int patch_register_file(linker_file_t lf,
	struct kpatch_metadata **patches, int pcount,
	struct kpatch_func_metadata **funcs, int fcount);

int patch_unregister_file(linker_file_t lf, int flags);

int patch_excluded(const char *name);

int patch_register(patch_set_t *patch);

int patch_unregister(patch_set_t *patch);

int patch_enable(patch_set_t *patch);

int patch_disable(patch_set_t *patch);

/*
 * Machine dependant functions
 */
int patch_validate_func(patch_func_t *func);

void patch_install_trampoline(patch_func_t *func);

void patch_restore_trampoline(patch_func_t *func);

#endif /* KPATCH_INTERNAL */

#endif /* _KERNEL */

#endif
