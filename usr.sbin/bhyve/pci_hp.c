
#include <sys/_param.h>
#include <sys/cdefs.h>
#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <pthread.h>
#include <vmmapi.h>

#include "acpi.h"
#include "acpi_device.h"
#include "pci_hp.h"
#include "amd64/inout.h"

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
pcihp_ioport_handler(struct vmctx *ctx __unused, int in, int port,
					 int bytes, uint32_t *eax, void *arg __unused) {
	int error;

	assert(port >= PCI_EMUL_HP_PORT && port < (PCI_EMUL_HP_PORT + PCI_EMUL_HP_LEN));
	if (port < PCI_EMUL_HP_EJ && !in) {
		return (-1);
	}
	if (bytes != 4) {
		return (-1);
	}

	error = 0;
	pthread_mutex_lock(&hp_lock);
	switch(port) {
		case PCI_EMUL_HP_PCIU:
			*eax = hp_status.pciu;
			break;
		case PCI_EMUL_HP_PCID:
			*eax = hp_status.pciu;
			break;
		case PCI_EMUL_HP_EJ:
			if (!in) {
				hp_status.bus0ej = *eax;
			} else {
				*eax = hp_status.bus0ej;
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
	int error;
#ifdef __amd64__
	struct inout_port iop;
	struct acpi_device *dev;

	error = acpi_device_create(&dev, dev, ctx, &pcihp_device_emul);
	if (error)
		goto err_out;

	error = acpi_device_add_res_fixed_ioport(dev, PCI_EMUL_HP_PORT,
	    PCI_EMUL_HP_LEN);
	if (error)
		goto err_out;

	bzero(&iop, sizeof(iop));
	iop.name = PCIHP_IOMEM_RANGE_NAME;
	iop.port = PCI_EMUL_HP_PORT;
	iop.size = PCI_EMUL_HP_LEN;
	iop.flags = IOPORT_F_INOUT;
	iop.handler = pcihp_ioport_handler;
	error = register_inout(&iop);
err_out:
#else
	error = -1;
#endif
	return (error);
}
