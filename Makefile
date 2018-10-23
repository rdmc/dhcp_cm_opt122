EXTRA_CFLAGS 	+= -o2 -Wall -I..

obj-m += dhcp_cm_opt122.o
#obj-m += m0.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
