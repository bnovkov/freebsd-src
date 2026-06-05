#ifndef _SYS_PATCH_H_
#define	_SYS_PATCH_H_

#include <sys/module.h>
#include <sys/queue.h>

#include <machine/patch.h>

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
	bool patched;
	void *old_addr;
	size_t old_size;
//	linker_file_t lf;
	uint8_t old_text[PATCH_TEXTLEN];
} patch_func_t;

int patch_excluded(const char *name);

int patch_load_set(patch_set_t *patch);

int patch_unload_set(patch_set_t *patch);

// Machine dependant below
int patch_validate_func(patch_func_t *func);

int patch_apply_func(patch_func_t *func, void *arg);

int patch_rollback_func(patch_func_t *func, void *arg);

#endif
