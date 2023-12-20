
.PATH: ${SRCTOP}/sys/amd64/pt

KMOD=   pt
SRCS=   pt.c pt.h device_if.h bus_if.h pt_ipi.S
SRCS+=  opt_hwpmc_hooks.h opt_kstack_pages.h
DPSRCS= assym.inc

pt_ipi.o:
	${CC} -c -x assembler-with-cpp -DLOCORE ${CFLAGS} \
            ${.IMPSRC} -o ${.TARGET}

.include <bsd.kmod.mk>
