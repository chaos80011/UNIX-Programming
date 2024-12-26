#!/bin/bash

cd mazemod
make clean
make
cd ..

rm rootfs/modules/maze.ko
cp mazemod/maze.ko rootfs/modules

cd rootfs
find . | cpio -o -H newc > rootfs.cpio
bzip2 -k rootfs.cpio
cd ..

rm dist/rootfs.cpio.bz2
mv rootfs/rootfs.cpio.bz2 dist

./qemu.sh