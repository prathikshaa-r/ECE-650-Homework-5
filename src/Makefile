CC=gcc
CCFLAGS=-std=gnu99 -Wall -Werror -pedantic -ggdb3

ifeq ($(KERNELRELEASE),)  

KERNELDIR ?= /lib/modules/$(shell uname -r)/build 
PWD := $(shell pwd)  

.PHONY: build clean clobber

build:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules  

clean:
	rm -rf *.o *~ core .depend .*.cmd *.order *.symvers *.ko *.mod.c sneaky_process

clobber:
	rm -rf *~

sneaky_process: sneaky_process.c
	$(CC) $(CCFLAGS) $< -o $@

else  

$(info Building with KERNELRELEASE = ${KERNELRELEASE}) 
obj-m :=    sneaky_mod.o

endif
