SHLIBDIR?= /lib

PACKAGE=lib${LIB}
LIB=	bhyve
SRCS=	config.c 	\
	pci.c
INCS=	bhyve/config.h		\
	bhyve/net_backends.h	\
	bhyve/pci.h
INCSDIR = ${INCLUDEDIR}/bhyve

INTERNALLIB=

SHLIB_MAJOR=	0
SHLIB_MINOR=	1
CFLAGS+= -I${.CURDIR}
LIBADD+= netgraph

MAN= libbhyve.3
.include <bsd.lib.mk>
