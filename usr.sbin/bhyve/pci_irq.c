/*
 * Copyright (c) 2025 Bojan Novković <bnovkov@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include "pci_irq.h"
#include "pci_emul.h"

void
pci_irq_route_dev(struct pci_devinst *pi, struct pci_irq *irq)
{
	pci_irq_route(pi->pi_vmctx, irq, pi->pi_slot, pi->pi_lintr.pin);
}
