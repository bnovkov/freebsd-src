#ifndef _SYS_KPATCH_H_
#define	_SYS_KPATCH_H_

#include <sys/types.h>

struct kpatch_set_metadata {
	const char *name;
	struct kpatch_func_metadata *funcs;
	int count;
	int flags;
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
 * Internal API of the subsystem below
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
struct kpatch_set {
	const char *name;
	TAILQ_HEAD(, kpatch_func) funcs;
	bool enabled;
	bool attached;
	linker_file_t lf;
	TAILQ_ENTRY(kpatch_set) link;
	struct sysctl_ctx_list ctx;
	struct sysctl_oid *oidp;
};

/*
 * Contains information about a single patched symbol
 */
struct kpatch_func {
	struct kpatch_set *patch;
	void *new_addr;
	const char *old_sym;
	unsigned old_sympos;
	void *old_addr;
	const char *old_obj;
	linker_file_t old_lf;
	bool patched;
	int old_size;
	uint8_t old_text[KPATCH_TEXTLEN];
	RB_ENTRY(kpatch_func) node;
	TAILQ_ENTRY(kpatch_func) link;
};

int kpatch_register(linker_file_t lf, struct kpatch_set_metadata **patches, int count);

int kpatch_unregister(linker_file_t lf, int flags);

// TODO: Should these be here or in machine/kpatch.h ?
int kpatch_func_validate(struct kpatch_func *func);

#endif /* KPATCH_INTERNAL */

#endif
