#include <sys/types.h>
#include <sys/cpuset.h>
#include <sys/patch.h>
#include <sys/types.h>
#include <sys/smp.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>

#include <machine/patch.h>

struct patch_arg {
	int patching_cpu;
	vm_offset_t *vas;
	uint8_t **insns;
	size_t *sizes;
	size_t cnt;
	struct patch_md_ctxt *md_ctxt;
};

static vm_offset_t patch_addr;

static void
patch_init(void *arg)
{
	patch_addr = patch_get_va();
}

SYSINIT(patch, SI_SUB_PATCH, SI_ORDER_SECOND, patch_init, NULL);

void __patch(void *arg) {

	struct patch_arg *data;
	vm_offset_t va;
	vm_page_t patch_page;
	uint8_t *insn;
	size_t size;
	int i;

	data = (struct patch_arg *)arg;
	for(i = 0; i < data->cnt; i++) {
		va = data->vas[i];
		insn = data->insns[i];
		size = data->sizes[i];

		patch_page = PHYS_TO_VM_PAGE(vtophys(va));
		before_patch(patch_page, data->md_ctxt);
		memcpy((void *)(patch_addr + (patch_addr & PAGE_MASK)), insn,
		    size);
		after_patch(arg->md_ctxt);
	}
}

static void
rendezvous_action(void *arg)
{
	struct patch_arg *data;

	data = (struct patch_arg *)arg;

	if (data->patching_cpu == curcpu) {
		__patch(data);
	}
}

void
patch_many(vm_offset_t *vas, uint8_t **insns, size_t *sizes, size_t cnt)
{
	struct patch_md_ctxt ctxt;
	struct patch_arg arg = {
		.patching_cpu = curcpu;
		.vas = vas;
		.insns = insns;
		.sizes = sizes;
		.cnt = cnt;
		.md_ctxt = &ctxt;
	};
	smp_rendezvous(NULL, rendezvous_action, NULL, &arg);
}
