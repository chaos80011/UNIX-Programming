obj-m     += maze.o
ccflags-y += -DEXPORT_SYMTAB

all:
	make -C ../dist/modulebuild M=$(PWD) modules

# mazemod: mazemod.c
# 	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	rm -f maze
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
	cp hello hellomod.ko ../rootfs/modules