CFLAGS=-O2
#CFLAGS=-g

sslproxy: sslproxy.c
	$(CC) -o $@ -Wall -Wno-parentheses $(CFLAGS) $+ -lssl -lcrypto

ssl_wrap: ssl_wrap.c
	$(CC) -o $@ -W -O2 -pthread $+ -lgnutls

dhcert: cert
	openssl dhparam 2048 >> ssl.pem

cert:
	openssl req -newkey rsa:2048 -nodes -keyout ssl.pem -subj /CN=localhost\
	| openssl x509 -req -signkey ssl.pem -sha256 -days 730 >> ssl.pem

clean:
	rm -f sslproxy
