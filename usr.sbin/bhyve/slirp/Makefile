.PATH: ${.CURDIR}/../

PROG= bhyve-slirp-helper
SRCS= slirp-helper.c
CFLAGS+= -I${.CURDIR}/../		\
	 -I${SRCTOP}/lib/libbhyve
LIBADD= bhyve nv
MAN=

BINDIR?= /usr/libexec

.include <bsd.prog.mk>
