CFLAGS=-O2
#CFLAGS=-g -O
BINDIR=/usr/local/sbin

sslproxy: sslproxy.c
	$(CC) -o $@ -Wall -Wno-parentheses $(CFLAGS) $+ -lssl -lcrypto

clean:
	rm -f sslproxy

install: sslproxy certgen
	strip --strip-all $<
	install -D $+ $(BINDIR)

uninstall:
	rm -f $(BINDIR)/sslproxy $(BINDIR)/certgen

server.pem:
	./certgen localhost "$@"
