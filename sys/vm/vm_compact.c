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
#include <vm/vm_phys.h>
#include <vm/vm_pagequeue.h>

#define VM_COMPACT_LOCK() mtx_lock(&compact_lock)
#define VM_COMPACT_UNLOCK() mtx_unlock(&compact_lock)

MALLOC_DEFINE(M_VMCOMPACT, "vm_compact_ctx", "memory compaction context");

static int vm_phys_compact_thresh = 300; /* 200 - 1000 */
static int sysctl_vm_phys_compact_thresh(SYSCTL_HANDLER_ARGS);
SYSCTL_OID(_vm, OID_AUTO, phys_compact_thresh, CTLTYPE_INT | CTLFLAG_RW, NULL,
    0, sysctl_vm_phys_compact_thresh, "I",
    "Fragmentation index threshold for memory compaction");

static struct mtx compact_lock;
static LIST_HEAD(, vm_compact_ctx) active_compactions[MAXMEMDOM];

struct vm_compact_ctx {
	vm_compact_search_fn search_fn;
	vm_compact_defrag_fn defrag_fn;

  vm_paddr_t start;
  vm_paddr_t end;

	int order;
	int domain;

  void *p_data;

	LIST_ENTRY(vm_compact_ctx) entries;
};

static int
sysctl_vm_phys_compact_thresh(SYSCTL_HANDLER_ARGS)
{
	int error;
	int new = vm_phys_compact_thresh;

	error = sysctl_handle_int(oidp, &new, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	if (new != vm_phys_compact_thresh) {
		if (new < 200) {
			new = 200;
		} else if (new > 1000) {
			new = 1000;
		}
		vm_phys_compact_thresh = new;
	}

	return (0);
}

static bool
vm_compact_job_overlaps(struct vm_compact_ctx *ctxp1,
    struct vm_compact_ctx *ctxp2)
{
        return (ctxp1->start <= ctxp2->start &&
                ctxp2->start <= ctxp1->end);
}

static  bool
vm_compact_check_range_domain(vm_paddr_t start, vm_paddr_t end)
{
        vm_page_t m1 = PHYS_TO_VM_PAGE(start);
        vm_page_t m2 = PHYS_TO_VM_PAGE(end);

        KASSERT(!(m1->flags & (PG_FICTITIOUS | PG_MARKER)) && !(m2->flags & (PG_FICTITIOUS | PG_MARKER)), ("Passed fictitious page in compaction range"));
        return vm_page_domain(m1) == vm_page_domain(m2);
}

void *
vm_compact_create_job(vm_compact_search_fn sfn, vm_compact_defrag_fn dfn,
    vm_compact_ctx_init_fn ctxfn, vm_paddr_t start, vm_paddr_t end, int order, int *error)
{
	struct vm_compact_ctx *ctxp;

	/* Arguments sanity check. */
	if (end <= start || order > (VM_NFREEORDER_MAX - 1)) {
		*error = (EINVAL);
		return (NULL);
	}

	/* Check whether 'start' and 'end' belong to the same domain. */
	if (!vm_compact_check_range_domain(start, end)) {
		*error = (ERANGE);
		return (NULL);
	}

	ctxp = malloc(sizeof(struct vm_compact_ctx), M_VMCOMPACT,
	    M_WAITOK | M_ZERO);

	ctxp->search_fn = sfn;
	ctxp->defrag_fn = dfn;
	ctxp->start = start;
	ctxp->order = order;
	ctxp->domain = vm_page_domain(PHYS_TO_VM_PAGE(start));

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
  int old_frag_idx, frag_idx;
	struct vm_compact_region r;
	struct vm_compact_ctx *ctxp = (struct vm_compact_ctx *)ctx;
	struct vm_compact_ctx *ctxp_tmp;
  size_t nrelocated = 0;

	VM_COMPACT_LOCK();
	/* Check if the requested compaction overlaps with an existing one. */
	LIST_FOREACH (ctxp_tmp, &active_compactions[ctxp->domain], entries) {
		if (vm_compact_job_overlaps(ctxp, ctxp_tmp)) {
			VM_COMPACT_UNLOCK();
			return (EINPROGRESS);
		}
	}

	LIST_INSERT_HEAD(&active_compactions[ctxp->domain], ctxp, entries);
	VM_COMPACT_UNLOCK();

  vm_domain_free_lock(VM_DOMAIN(ctxp->domain));
	frag_idx = old_frag_idx = vm_phys_fragmentation_index(ctxp->order,
	    ctxp->domain);
  vm_domain_free_unlock(VM_DOMAIN(ctxp->domain));

	/* No need to compact if fragmentation is below the threshold. */
	if (old_frag_idx < vm_phys_compact_thresh) {
		goto cleanup;
	}


	/* Run compaction until the fragmentation metric stops improving. */
	do {
		// TODO: rework to use end_fn later on
		old_frag_idx = frag_idx;

		ctxp->search_fn(&r, ctxp->domain, ctxp->p_data);
		nrelocated += ctxp->defrag_fn(&r, ctxp->domain, ctxp->p_data);

    vm_domain_free_lock(VM_DOMAIN(ctxp->domain));
		frag_idx = vm_phys_fragmentation_index(ctxp->order, ctxp->domain);
    vm_domain_free_unlock(VM_DOMAIN(ctxp->domain));
	} while ((old_frag_idx - frag_idx) > 20);

 cleanup:
	VM_COMPACT_LOCK();
	LIST_REMOVE(ctxp, entries);
	VM_COMPACT_UNLOCK();

  printf("relocated %zu pages\n", nrelocated);

	return 0;
}


static void
vm_compact_init(void *arg){
        mtx_init(&compact_lock, "vm_compact", NULL, MTX_DEF);
        for(int i=0; i<MAXMEMDOM; i++)
                LIST_INIT(&active_compactions[i]);
}

SYSINIT(vm_compact, SI_SUB_VM_CONF, SI_ORDER_ANY, vm_compact_init, NULL);
