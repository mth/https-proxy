#CFLAGS=-O2
CFLAGS=-g -O
BINDIR=/usr/local/sbin

https-proxy: https-proxy.c
	$(CC) -o $@ -Wall -Wno-parentheses $(CFLAGS) $+ -lssl -lcrypto

clean:
	rm -f https-proxy

install: https-proxy certgen
	strip --strip-all $<
	install -D $+ $(BINDIR)

uninstall:
	rm -f $(BINDIR)/https-proxy $(BINDIR)/certgen

server.pem:
	./certgen localhost "$@"
