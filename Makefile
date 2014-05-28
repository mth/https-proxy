CFLAGS = -O2
#CFLAGS = -g -O
BINDIR = /usr/local/sbin

LDFLAGS = -lssl -lcrypto

# autodetect systemd
ifneq ($(shell pkg-config --exists libsystemd-daemon || echo NONE),NONE)
CFLAGS += -DUSE_SYSTEMD $(shell pkg-config --cflags libsystemd-daemon)
LDFLAGS += $(shell pkg-config --libs libsystemd-daemon)
endif

https-proxy: https-proxy.c
	$(CC) -o $@ -Wall -Wno-parentheses $(CFLAGS) $+ $(LDFLAGS)

clean:
	rm -f https-proxy

install: https-proxy certgen
	strip --strip-all $<
	install -D $+ $(BINDIR)

uninstall:
	rm -f $(BINDIR)/https-proxy $(BINDIR)/certgen

server.pem:
	./certgen localhost "$@"
