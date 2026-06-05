#ifndef _MACHINE_PATCH_H_
#define _MACHINE_PATCH_H_

#include <sys/patch.h>

int patch_validate_func(patch_func_t *func);

int patch_apply_func(patch_func_t *func, void *arg);

int patch_rollback_func(patch_func_t *func, void *arg);

#endif
