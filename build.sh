A=CONF
if [ "$1" = "fast" ]; then
	A=FAST
fi

#make -j12 TARGET=arm64 KERN${A}=GENERIC-MORELLO cleankernel || exit 1
make -j12 TARGET=arm64 KERN${A}=GENERIC-MORELLO buildkernel || exit 1

cp /usr/obj/usr/home/br/dev/freebsd-morello/arm64.aarch64/sys/GENERIC-MORELLO/kernel /tftpboot/root/boot/kernel/kernel || exit 2

scp /usr/obj/usr/home/br/dev/freebsd-morello/arm64.aarch64/sys/GENERIC-MORELLO/kernel 10.2.0.156:~/modules/boot/kernel/ || exit 3

# Coresight
scp /usr/obj/usr/home/br/dev/freebsd-morello/arm64.aarch64/sys/GENERIC-MORELLO/modules/usr/home/br/dev/freebsd-morello/sys/modules/coresight/*/*ko 10.2.0.156:~/modules/ || exit 4

# SPE
scp /usr/obj/usr/home/br/dev/freebsd-morello/arm64.aarch64/sys/GENERIC-MORELLO/modules/usr/home/br/dev/freebsd-morello/sys/modules/spe/spe.ko 10.2.0.156:~/modules/ || exit 4

# hwt.ko
scp /usr/obj/usr/home/br/dev/freebsd-morello/arm64.aarch64/sys/GENERIC-MORELLO/modules/usr/home/br/dev/freebsd-morello/sys/modules/hwt/hwt.ko 10.2.0.156:~/modules/ || exit 5

# hwt
scp /usr/obj/usr/home/br/dev/freebsd-morello/arm64.aarch64/usr.sbin/hwt/hwt 10.2.0.156:~/
