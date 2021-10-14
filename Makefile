KMOD=isn_sync
SRCS=isn_sync.c

CLEANDIRS+=.kconf

KERNCONF!=uname -i
KERNCONFDIR=/usr/src/sys/${MACHINE_ARCH}/conf

.if !empty(KERNCONF)
SRCS+=.kconf/opt_global.h
CFLAGS+=-include .kconf/opt_global.h
.endif

.kconf/opt_global.h: ${KERNCONFDIR}/${KERNCONF}
	cd ${KERNCONFDIR} && config -d ${.CURDIR}/.kconf ${KERNCONF}

.include <bsd.kmod.mk>
