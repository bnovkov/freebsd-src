.if !defined(KERNFILE)
.if defined(KERNBUILDDIR)
KERNFILE=	${KERNBUILDDIR}/kernel.full
.else
KERNFILE=	/usr/obj/usr/src/${MACHINE}.${MACHINE_ARCH}/sys/GENERIC/kernel.full
.endif
.endif

BUILDPATCH?=	buildpatch

PROG=		${KMOD}.pre.ko

CFLAGS+=	-I${SYSDIR}/../tools/tools/buildpatch

.include <bsd.kmod.mk>

all: ${KMOD}.ko

${KMOD}.ko: ${PROG}
	${BUILDPATCH} ${PROG} ${.TARGET} ${KERNFILE}

CLEANFILES+=	${KMOD}.ko
