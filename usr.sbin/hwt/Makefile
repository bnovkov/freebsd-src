PROG_CXX=	hwt
MAN=

CFLAGS+= -I${SRCTOP}/lib/libpmcstat -I${SRCTOP}/sys

LIBADD= elf pmcstat xo util

SRCS=	hwt.c			\
	hwt_fmt.c		\
	hwt_elf.c		\
	hwt_process.c		\
	hwt_record.c		\
	libpmcstat_stubs.c

.if ${MACHINE_CPUARCH} == "aarch64"
SRCS+=	hwt_coresight.c hwt_spe.c
LIBADD+= opencsd
.elif ${MACHINE_CPUARCH} == "amd64"
SRCS+=  hwt_pt.c	 \
	 pt/pt_decode.c  \
	 pt/pt_dump.c 	 \
	 pt/pt_fmt.c
LIBADD+= ipt
.endif

.include <bsd.prog.mk>
