#ifndef PCIHP_H_
#define PCIHP_H_

#define PCI_EMUL_HP_PORT 0xae00
#define PCI_EMUL_HP_PCST PCI_EMUL_HP_PORT
#define PCI_EMUL_HP_PCIU PCI_EMUL_HP_PCST
#define PCI_EMUL_HP_PCID (PCI_EMUL_HP_PCST + 0x4)
#define PCI_EMUL_HP_EJ   (PCI_EMUL_HP_PORT + 0x8)
#define PCI_EMUL_HP_LEN  0xc

struct vmctx;

int pci_hp_init(struct vmctx *ctx);
int pci_hp_request_up(struct vmctx *ctx, int bus, int slot);
#endif // PCIHP_H_
