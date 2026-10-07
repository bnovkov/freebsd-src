#ifndef _SYS_KPATCH_H_
#define	_SYS_KPATCH_H_

#include <sys/types.h>

struct kpatch_metadata {
	int version;
	size_t build_id_len;
	uint8_t build_id[32];
	struct kpatch_set_metadata *sets;
	size_t sets_count;
	struct kpatch_reloc_metadata *relocs;
	size_t relocs_count;
};

// TODO: Maybe add a enable-on-load flag for sets. Mainly for preloading
struct kpatch_set_metadata {
	const char *name;
	struct kpatch_func_metadata *funcs;
	size_t funcs_count;
	int flags;
	int (*pre_patch)(void);
	void (*post_patch)(int);
	int (*pre_unpatch)(void);
	void (*post_unpatch)(int);
};

// TODO: Does it make sense to add a separate entity for objects?
//struct kpatch_obj_metdata {
//	const char *name;
//};

struct kpatch_func_metadata {
	void *new_addr;
	const char *old_sym;
	const char *old_obj;
	int sympos;
	int flags;
};

struct kpatch_reloc_metadata {
	const char *sym;
	const char *obj;
	int sympos;
	int flags;
};

#define KPATCH_METADATA		"kpatch_info"

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
	int (*pre_patch)(void);
	void (*post_patch)(int);
	int (*pre_unpatch)(void);
	void (*post_unpatch)(int);
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
	unsigned old_size;
	uint8_t old_text[KPATCH_TEXTLEN];
	RB_ENTRY(kpatch_func) node;
	TAILQ_ENTRY(kpatch_func) link;
};

int kpatch_detect(linker_file_t lf);

int kpatch_register(linker_file_t lf);

int kpatch_unregister(linker_file_t lf, int flags);

int kpatch_lookup_elf(linker_file_t lf, Elf_Sym *sym, Elf_Addr *res);

// TODO: Should these be here or in machine/kpatch.h ?
int kpatch_func_validate(struct kpatch_func *func);

void kpatch_install_trampoline(struct kpatch_func *func);

void kpatch_restore_trampoline(struct kpatch_func *func);

void kpatch_flush_icache(void);

#endif /* KPATCH_INTERNAL */

#endif
