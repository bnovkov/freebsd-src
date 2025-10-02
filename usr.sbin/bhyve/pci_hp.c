
#include <sys/_param.h>
#include <sys/param.h>
#include <sys/cdefs.h>
#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <pthread.h>
#include <vmmapi.h>

#include <dev/pci/pcireg.h>

#include "acpi.h"
#include "acpi_device.h"
#include "pci_hp.h"
#include "amd64/inout.h"
