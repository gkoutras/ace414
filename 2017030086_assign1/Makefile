CC = gcc
CFLAGS = -Wall -g -c
LDFLAGS = -lm -lgmp

SOURCES_DH = dh_main.c dh.c util.c
OBJECTS_DH = dh_main.o dh.o util.o

SOURCES_RSA = rsa_main.c rsa.c util.c
OBJECTS_RSA = rsa_main.o rsa.o util.o

all: dh_assign_1 rsa_assign_1

dh_assign_1: $(OBJECTS_DH)
	$(CC) $(OBJECTS_DH) -o dh_assign_1 $(LDFLAGS)

rsa_assign_1: $(OBJECTS_RSA)
	$(CC) $(OBJECTS_RSA) -o rsa_assign_1 $(LDFLAGS)

dh_main.o: dh_main.c
	$(CC) $(CFLAGS) dh_main.c

dh.o: dh.c
	$(CC) $(CFLAGS) dh.c

rsa_main.o: rsa_main.c
	$(CC) $(CFLAGS) rsa_main.c

rsa.o: rsa.c
	$(CC) $(CFLAGS) rsa.c

util.o: util.c
	$(CC) $(CFLAGS) util.c

clean:
	rm -f $(OBJECTS_DH) $(OBJECTS_RSA) dh_assign_1 rsa_assign_1
