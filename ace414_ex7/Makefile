CC=gcc
CFLAGS=-ggdb -fno-stack-protector -z execstack -Wall -no-pie

all: pwn.c
	$(CC) $(CFLAGS) -o bof pwn.c

clean: 
	rm -f bof payload.bin
	