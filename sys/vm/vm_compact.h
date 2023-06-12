/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023. Bojan Novković <bojan.novkovic@kset.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <vm/vm.h>
#include <sys/malloc.h>

MALLOC_DECLARE(M_VMCOMPACT);

struct vm_compact_region {
	vm_paddr_t start;
	vm_paddr_t end;
  STAILQ_ENTRY(vm_compact_region) entries;
};
typedef struct vm_compact_region *vm_compact_region_t;

STAILQ_HEAD(vm_compact_region_head, vm_compact_region);

typedef int (*vm_compact_search_fn)(vm_compact_region_t *, int, void *);
typedef size_t (*vm_compact_defrag_fn)(vm_compact_region_t, int, void *);
typedef bool (*vm_compact_end_fn)(void);
typedef void (*vm_compact_ctx_init_fn)(void **);


void *vm_compact_create_job(vm_compact_search_fn sfn, vm_compact_defrag_fn dfn,
                            vm_compact_ctx_init_fn ctxfn, vm_paddr_t start, vm_paddr_t end, int order, int *error);
void vm_compact_free_job(void *ctx);
int vm_compact_run(void *ctx);
