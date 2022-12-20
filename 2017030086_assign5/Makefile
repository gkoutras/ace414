CC = gcc
CFLAGS = -O2 -Wall -pedantic -g
LDFLAGS = -lpcap

SOURCES = pcap_ex.c

all: pcap_ex

pcap_ex: pcap_ex.c
	$(CC) $(CCFLAGS) $(SOURCES) -o pcap_ex $(LDFLAGS)

clean:
	rm -rf pcap_ex log.txt