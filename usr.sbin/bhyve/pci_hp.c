
#include <sys/_param.h>
#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <pthread.h>
#include <vmmapi.h>

#include "acpi.h"
#include "acpi_device.h"
#include "mem.h"
#include "pci_hp.h"

#define PCIHP_ACPI_HID "PNP0A06"
#define PCIHP_ACPI_DEVNAME "PHPS"
#define PCIHP_IOMEM_RANGE_NAME "PCI Hotplug state"

struct tpm_device {
	struct vmctx *vm_ctx;
	struct acpi_device *acpi_dev;
};

static const struct acpi_device_emul pcihp_device_emul = {
.name = PCIHP_ACPI_DEVNAME,
.hid = PCIHP_ACPI_HID,
};

static struct hpstate {
	uint32_t pciu;
	uint32_t pcid;
	uint32_t bus0ej;
} hp_status;

static pthread_mutex_t hp_lock = PTHREAD_MUTEX_INITIALIZER;

static int
pcihp_iomem_handler(struct vcpu *vcpu __unused, int dir, uint64_t addr, int size,
				   uint64_t *val, void *arg1  __unused, long arg2 __unused) {
	uint64_t offset;
	int error;

	// TODO: assert 4 byte granularity
	assert(size == sizeof(uint32_t));
	offset = addr - PCI_EMUL_HP_PORT;
	if (offset < PCI_EMUL_HP_EJ && dir == MEM_F_WRITE) {
		return (-1);
	}
	error = 0;
	pthread_mutex_lock(&hp_lock);
	switch(offset) {
		case PCI_EMUL_HP_PCIU:
			*val = hp_status.pciu;
			break;
		case PCI_EMUL_HP_PCID:
			*val = hp_status.pciu;
			break;
		case PCI_EMUL_HP_EJ:
			if (dir == MEM_F_WRITE) {
				hp_status.bus0ej = *val;
			} else {
				*val = hp_status.bus0ej;
			}
			break;
		default:
			error = -1;
	}
	pthread_mutex_unlock(&hp_lock);

	return (error);
}

int pci_hp_request_up(struct vmctx *ctx, int bus, int slot) {

	if (bus != 0) {
		printf("%s: bus 0 only please\n", __func__);
		return (-1);
	}

	if (slot < 0 || slot > 32) {
		printf("%s: slot %d out of range\n", __func__, slot);
		return (-1);
	}

	if ((hp_status.pciu & (1 << slot)) != 0) {
		printf("%s: slot %d has pending hotplug request\n", __func__, slot);
		return (-1);
	}

	hp_status.pciu |= (1 << slot);
	acpi_raise_gpe(ctx, GPE_HP);

	return (0);
}

int pci_hp_init(struct vmctx *ctx) {
	struct mem_range mr;
	struct acpi_device *dev;
	int error;

	error = acpi_device_create(&dev, dev, ctx, &pcihp_device_emul);
	if (error)
		goto err_out;

	error = acpi_device_add_res_fixed_ioport(dev, PCI_EMUL_HP_PORT,
	    PCI_EMUL_HP_LEN);
	if (error)
		goto err_out;

	bzero(&mr, sizeof(struct mem_range));
	mr.name = PCIHP_IOMEM_RANGE_NAME;
	mr.flags = MEM_F_RW;
	mr.handler = pcihp_iomem_handler;
	mr.base = PCI_EMUL_HP_PORT;
	mr.size = PCI_EMUL_HP_LEN;

err_out:
	return (error);
}
