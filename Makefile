obj-m += pfkm.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
load:
	# load module passing
	sudo insmod ./pfkm.ko
	
unload:
	sudo rmmod pfkm
	
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean