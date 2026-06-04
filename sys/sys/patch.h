#ifndef _SYS_PATCH_H_
#define	_SYS_PATCH_H_

#include <sys/module.h>
#include <sys/queue.h>

/*
 * Represent a whole patch, and contains metadata and a list of funcs
 */
typedef struct patch_set {
	struct patch_func *funcs;

	/* private fields */
	bool enabled;
	module_t mod;
	TAILQ_ENTRY(patch_set) link;
} patch_set_t;

/*
 * Contains information about a single patched symbol
 */
typedef struct patch_func {
	const char *old_sym;
	unsigned old_sympos;
	void *new_addr;

	/* private fields */
	void *old_addr;
	size_t old_size;
//	linker_file_t lf;
} patch_func_t;

int patch_excluded(const char *name);

int patch_load_set(patch_set_t *patch);

int patch_unload_set(patch_set_t *patch);

#endif
