CC = gcc
CFLAGS = -Wall -c
LDFLAGS = -L/usr/lib -lssl -lcrypto

SOURCES_S = server.c
OBJECTS_S = server.o

SOURCES_C = client.c
OBJECTS_C = client.o

all: server client

server: $(OBJECTS_S)
	$(CC) $(OBJECTS_S) -o server $(LDFLAGS)

client: $(OBJECTS_C)
	$(CC) $(OBJECTS_C) -o client $(LDFLAGS)

server.o: server.c
	$(CC) $(CFLAGS) server.c

client.o: client.c
	$(CC) $(CFLAGS) client.c

clean:
	rm -f $(OBJECTS_S) $(OBJECTS_C) server client
