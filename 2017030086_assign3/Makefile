all: rsa.o logger acmonitor test_aclog

rsa.o: rsa.c
	gcc -O2 -Wall -g -c rsa.c

logger: logger.c
	gcc -O2 -Wall -g -fPIC -shared -o logger.so logger.c -lcrypto -ldl -lm -lgmp

acmonitor: acmonitor.c 
	gcc -O2 -g rsa.o acmonitor.c -o acmonitor -lm -lgmp

test_aclog: test_aclog.c 
	gcc -O2 -g test_aclog.c -o test_aclog

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

clean:
	rm -rf rsa.o
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
	rm -rf file_* helloworld test
