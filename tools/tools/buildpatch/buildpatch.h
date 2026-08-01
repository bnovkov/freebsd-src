#ifndef BUILDPATCH_H
#define BUILDPATCH_H

#include <sys/types.h>

#define PATCH_USING_SYMPOS 0x1

struct set_metadata {
	const char *name;
	long flags;
};

struct func_metadata {
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

struct reloc_metadata {
	const char *local_sym;
	const char *real_sym;
	const char *real_obj;
	union {
		const char *real_file;
		long sympos;
	} uniquifier;
	long flags;
};

#define PATCH_SET_SECTION	".buildpatch.sets"
#define PATCH_FUNC_SECTION	".buildpatch.funcs"
#define PATCH_RELOC_SECTION	".buildpatch.relocs"

#define PATCH_CONCAT(name, uniquifier)	__patch_##name##_##uniquifier

#define PATCH_DECLARE(name, flags) \
	 __used __section(PATCH_SET_SECTION) \
	static struct set_metadata PATCH_CONCAT(name, info) = { \
		#name, flags \
	};

#define PATCH_FUNC_FULL(patch, new_sym, old_sym, old_obj, uniquifier, flags) \
	 __used __section(PATCH_FUNC_SECTION) \
	static struct func_metadata PATCH_CONCAT(patch, func__##new_sym) = { \
		#patch, #new_sym, new_sym, old_sym, old_obj, { uniquifier }, flags \
	};

#define PATCH_FUNC(patch, new_sym, old_sym, old_obj, old_file) \
	PATCH_FUNC_FULL(patch, new_sym, old_sym, old_obj, old_file, 0)

#define PATCH_RELOC_FULL(local, sym, obj, uniquifier, flags) \
	__used __section(PATCH_RELOC_SECTION) \
	static struct reloc_metadata PATCH_CONCAT(, reloc__##local) = { \
		#local, sym, obj, { uniquifier }, flags \
	};

#define PATCH_RELOC(local, sym, obj, file) \
	PATCH_RELOC_FULL(local, sym, obj, file, 0)

#endif
