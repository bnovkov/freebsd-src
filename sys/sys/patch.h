#ifdef _KERNEL
#ifndef PATCH_H
#define PATCH_H

/*
 * Forward declaration of a struct, defined separately for each architecture in
 * <machine/patch.h>
 */

struct patch_md_ctxt;

void patch_many(vm_offset_t *vas, uint8_t **insns, size_t *sizes, size_t cnt);

#endif
#endif
