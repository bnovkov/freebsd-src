# $FreeBSD$

.PATH:	${SRCTOP}/sys/arm64/coresight

KMOD	= coresight
SRCS	=			\
	coresight.c		\
	coresight_cmd.c		\
	coresight_fdt.c		\
	coresight_if.c		\
	coresight_if.h

.if defined(WITH_ACPI)
SRCS	+= coresight_acpi.c
.endif

.include <bsd.kmod.mk>
