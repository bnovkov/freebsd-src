/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023. Bojan Novković <bnovkov@freebsd.org>
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/sysctl.h>

#include <vm/vm.h>
#include <vm/vm_compact.h>
#include <vm/vm_page.h>
#include <vm/vm_pagequeue.h>
#include <vm/vm_phys.h>

#define VM_COMPACT_LOCK() mtx_lock(&compact_lock)
#define VM_COMPACT_UNLOCK() mtx_unlock(&compact_lock)

MALLOC_DEFINE(M_VMCOMPACT, "vm_compact_ctx", "memory compaction context");

static struct mtx compact_lock;
static LIST_HEAD(, vm_compact_ctx) active_compactions[MAXMEMDOM];

struct vm_compact_ctx {
	vm_compact_search_fn search_fn;
	vm_compact_defrag_fn defrag_fn;

	vm_paddr_t start;
	vm_paddr_t end;

	int order;
	int domain;
	struct vm_compact_region_head regions;

	void *p_data;

	LIST_ENTRY(vm_compact_ctx) entries;
};

static bool
vm_compact_job_overlaps(struct vm_compact_ctx *ctxp1,
    struct vm_compact_ctx *ctxp2)
{
	return (ctxp1->start <= ctxp2->start && ctxp2->start <= ctxp1->end);
}

void *
vm_compact_create_job(vm_compact_search_fn sfn, vm_compact_defrag_fn dfn,
    vm_compact_ctx_init_fn ctxfn, vm_paddr_t start, vm_paddr_t end, int order,
    int domain, int *error)
{
	struct vm_compact_ctx *ctxp;
	/* Arguments sanity check. */
	if (end <= start || order > (VM_NFREEORDER_MAX - 1)) {
		*error = (EINVAL);
		return (NULL);
	}

	ctxp = malloc(sizeof(struct vm_compact_ctx), M_VMCOMPACT,
	    M_WAITOK | M_ZERO);

	ctxp->search_fn = sfn;
	ctxp->defrag_fn = dfn;
	ctxp->start = start;
	ctxp->order = order;
	ctxp->domain = domain;
	SLIST_INIT(&ctxp->regions);

	ctxfn(&ctxp->p_data);

	return ((void *)ctxp);
}

void
vm_compact_free_job(void *ctx)
{
	free(ctx, M_VMCOMPACT);
}

int
vm_compact_run(void *ctx)
{
	struct vm_compact_ctx *ctxp = (struct vm_compact_ctx *)ctx;
	struct vm_compact_ctx *ctxp_tmp;
	int retval;

	VM_COMPACT_LOCK();
	/* Check if the requested compaction overlaps with an existing one. */
	LIST_FOREACH (ctxp_tmp, &active_compactions[ctxp->domain], entries) {
		if (vm_compact_job_overlaps(ctxp, ctxp_tmp)) {
			VM_COMPACT_UNLOCK();
			return (-EINPROGRESS);
		}
	}

	LIST_INSERT_HEAD(&active_compactions[ctxp->domain], ctxp, entries);
	VM_COMPACT_UNLOCK();

	/* Run compaction job. */
	if (ctxp->search_fn(&ctxp->regions, ctxp->domain, ctxp->p_data)) {
		retval = 0;
		goto cleanup;
	}

	retval = ctxp->defrag_fn(&ctxp->regions, ctxp->domain, ctxp->p_data);

cleanup:
	VM_COMPACT_LOCK();
	LIST_REMOVE(ctxp, entries);
	VM_COMPACT_UNLOCK();

	return retval;
}

static void
vm_compact_init(void *arg)
{
	mtx_init(&compact_lock, "vm_compact", NULL, MTX_DEF);
	for (int i = 0; i < MAXMEMDOM; i++)
		LIST_INIT(&active_compactions[i]);
}

SYSINIT(vm_compact, SI_SUB_KMEM + 2, SI_ORDER_ANY, vm_compact_init, NULL);
