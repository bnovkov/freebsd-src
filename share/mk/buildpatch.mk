.if !defined(KERNFILE)
.if defined(KERNBUILDDIR)
KERNFILE=	${KERNBUILDDIR}/kernel.full
.else
KERNFILE=	/usr/obj/usr/src/${MACHINE}.${MACHINE_ARCH}/sys/GENERIC/kernel.full
.endif
.endif

BUILDPATCH?=	buildpatch

CFLAGS+=	-I${SYSDIR}/../tools/tools/buildpatch

.include <bsd.kmod.mk>

all: .buildpatch_done
load: .buildpatch_done
realinstall: .buildpatch_done

.buildpatch_done: ${KMOD}.ko
	@mv ${KMOD}.ko ${KMOD}.pre.ko
	@${BUILDPATCH} ${KMOD}.pre.ko ${KMOD}.ko ${KERNFILE}
	@touch ${.TARGET}

CLEANFILES+=	${KMOD}.pre.ko .buildpatch_done
