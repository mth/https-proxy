CFLAGS=-O2
#CFLAGS=-g -O

sslproxy: sslproxy.c
	$(CC) -o $@ -Wall -Wno-parentheses $(CFLAGS) $+ -lssl -lcrypto

clean:
	rm -f sslproxy

server.pem:
	./certgen localhost "$@"
