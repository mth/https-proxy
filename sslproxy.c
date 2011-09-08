#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <poll.h>
#include <ctype.h>

#define MAX_FDS 512
#define expect(v) if (!(v)) { fputs("** ERROR " #v "\n", stderr); exit(1); }
#define SHA256_LEN 32

void OPENSSL_cpuid_setup();
void RAND_cleanup();

typedef struct buf {
	int len;
	int start;
	char data[16384];
} *buf;

typedef struct con {
	SSL *s;
	buf buf;
	struct con *other;
} *con;

typedef struct host {
	struct addrinfo *ai;
	struct host *next;
	char name[1];
} *host;

typedef struct digest {
	host hosts;
	struct digest *next;
	char value[SHA256_LEN];
} *digest;

static SSL_CTX *ctx;
static struct pollfd ev[MAX_FDS];
static struct con cons[MAX_FDS];
static int fd_count;
static int fd_limit = MAX_FDS;
static int server_port = 443;
static int host_idx;
static digest digests;

static void rm_conn(int n) {
	con c = cons + n;

	//fprintf(stderr, "rm_conn(%d): close(%d)\n", n, ev[n].fd);
	SSL_free(c->s);
	free(c->buf);
	if (c->other) {
		c->other->other = NULL;
		if (c->other - cons >= fd_count) 
			rm_conn(c->other - cons);
	}
	if (n >= fd_count) {
		cons[n] = cons[fd_limit++];
		return;
	}
	close(ev[n].fd);
	if (n < --fd_count) {
		ev[n] = ev[fd_count];
		*c = cons[fd_count];
		if (c->other)
			c->other->other = c;
	}
}

static int verify(X509_STORE_CTX *s, void *arg) {
	SSL *ssl;
	digest i;
	unsigned char md[SHA256_LEN];
	unsigned len = sizeof md;
	const EVP_MD *alg = EVP_sha256();

	if (EVP_MD_size(alg) != len || !X509_digest(s->cert, alg, md, &len) ||
	    !(ssl = X509_STORE_CTX_get_app_data(s))) {
		s->error = X509_V_ERR_APPLICATION_VERIFICATION;
		return 0;
	}
	ERR_clear_error();
	for (i = digests; i; i = i->next) {
		if (!memcmp(i->value, md, sizeof md)) {
			while (i && !i->hosts)
				i = i->next;
			if (!i)
				break;
			if (SSL_set_ex_data(ssl, host_idx, i->hosts))
				return 1;
			s->error = X509_V_ERR_APPLICATION_VERIFICATION;
			return 0;
		}
	}
	s->error = X509_V_ERR_CERT_REJECTED;
	return 0;
}

static void init_context() {
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OPENSSL_cpuid_setup();
	EVP_add_cipher(EVP_aes_128_cbc());
	EVP_add_cipher(EVP_aes_192_cbc());
	EVP_add_cipher(EVP_aes_256_cbc());
	EVP_add_digest(EVP_sha1());
	EVP_add_digest(EVP_sha224());
	EVP_add_digest(EVP_sha256());
	signal(SIGPIPE, SIG_IGN);

	host_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	expect(host_idx >= 0);
	expect(ctx = SSL_CTX_new(TLSv1_server_method()));
	SSL_CTX_set_cert_verify_callback(ctx, verify, NULL);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |
	                   SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
}

static void free_context() {
	ERR_free_strings();
	ERR_remove_state(0);
	RAND_cleanup();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

static int load_keycert(const char *fn) {
	FILE *f;
	EVP_PKEY *key;
	X509 *cert;
	DH *dh;

	if (!(f = fopen(fn, "r"))) {
		perror(fn);
		return 0;
	}
	if (!(key = PEM_read_PrivateKey(f, NULL, NULL, NULL))) {
		fprintf(stderr, "%s: invalid private key\n", fn);
		fclose(f);
		return 0;
	}
	expect(SSL_CTX_use_PrivateKey(ctx, key));
	if (!(cert = PEM_read_X509(f, NULL, NULL, NULL))) {
		fprintf(stderr, "%s: invalid certificate\n", fn);
		fclose(f);
		return 0;
	}
	expect(SSL_CTX_use_certificate(ctx, cert));
	dh = PEM_read_DHparams(f, NULL, NULL, NULL);
	fclose(f);
	if (dh) {
		ERR_clear_error();
		int ok = SSL_CTX_set_tmp_dh(ctx, dh);
		DH_free(dh);
		if (!ok) {
			ERR_print_errors_fp(stderr);
			fprintf(stderr, "%s: invalid DH parameters\n", fn);
			return 0;
		}
	} else {
		fprintf(stderr, "No DH parameters\n");
	}
	ERR_clear_error();
	if (SSL_CTX_check_private_key(ctx))
		return 1;
	ERR_print_errors_fp(stderr);
	fprintf(stderr, "%s: invalid key-certificate pair\n", fn);
	return 0;
}

static int add_digest(int len, char *dig) {
	unsigned i, v;
	digest d;

	if (len != 64)
		return 0;

	expect(d = malloc(sizeof(struct digest)));
	d->hosts = NULL;
	d->next = digests;

	for (i = 0; i < 32; ++i) {
		if (sscanf(dig + i * 2, "%02x", &v) <= 0) {
			free(d);
			return 0;
		}
		d->value[i] = v;
	}
	digests = d;
	return 1;
}

static int add_host(char *name) {
	char *node, *service;
	struct addrinfo hints, *r = NULL;
	int res;
	host h;

	if ((node = strpbrk(name, " \t")))
		*(node++) = 0;
	else
		node = name;

	expect(h = malloc(sizeof(struct host) + strlen(name)));
	strcpy(h->name, name);

	if ((service = strchr(node, ':')))
		*(service++) = 0;
	if (!service || node == name)
		service = "80";
	node += strspn(node, " \t");

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;
	if ((res = getaddrinfo(node, service, &hints, &r)) || !r) {
		fprintf(stderr, "Cannot resolve %s:%s: %s\n",
		        node, service, gai_strerror(res));
		free(h);
		return 0;
	}
	h->ai = r;
	h->next = digests->hosts;
	digests->hosts = h;
	return 1;
}

static int load_conf(const char *fn) {
	char what[10];
	char buf[256];
	FILE *f;
	int cert_loaded = 0;;

	if (!(f = fopen(fn, "r"))) {
		perror(fn);
		return 0;
	}

	while (fscanf(f, "%9s ", what) && fgets(buf, sizeof buf, f)) {
		int n = strlen(buf);
		while (--n >= 0 && buf[n] > 0 && buf[n] <= ' ')
			buf[n] = 0;
		++n;
		if (!strcmp(what, "sha256")) {
			if (!add_digest(n, buf))
				fprintf(stderr, "%s: invalid hash %s\n", fn, buf);
		} else if (!strcmp(what, "cert")) {
			if (cert_loaded)
				fprintf(stderr, "%s: duplicate cert entry\n", fn);
			else if (!load_keycert(buf))
				return 0;
			cert_loaded = 1;
		} else if (!strcmp(what, "allow")) {
			if (!digests)
				fprintf(stderr, "%s: allow must follow hash\n", fn);
			else if (!add_host(buf))
				fprintf(stderr, "%s: invalid allow directive: %s\n", fn, buf);
		} else if (!strcmp(what, "port")) {
			if (!sscanf(buf, "%d", &server_port))
				fprintf(stderr, "%s: invalid server port %s\n", fn, buf);
		} else if (*what != '#') {
			fprintf(stderr, "%s: garbage definition %s\n", fn, what);
		}
	}
	return cert_loaded || load_keycert("ssl.pem");
}

static int prepare_sock(int fd, int opt) {
	if (!opt || fcntl(fd, F_SETFL, (long) O_NONBLOCK)) {
		close(fd);
		return 0;
	}
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof opt);
	setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &opt, sizeof opt);
	return 1;
}

static int forward(con c, host h) {
	con cp;
	int fd = -1;

	if (fd_count >= fd_limit ||
	    (fd = socket(h->ai->ai_family, h->ai->ai_socktype, h->ai->ai_protocol))
			< 0 || !prepare_sock(fd, 1))
		goto close;

	if (connect(fd, h->ai->ai_addr, h->ai->ai_addrlen) &&
			errno != EINPROGRESS) {
		close(fd);
close:	rm_conn(c - cons);
		return 0;
	}

	ev[fd_count].fd = fd;
	ev[fd_count].events = POLLOUT;
	cons[fd_count] = *(cp = c->other);
	c->other = cons + fd_count++;
	if (cp > cons + fd_limit) {
		*cp = cons[fd_limit];
		cp->other = cp;
	}
	++fd_limit;
	return 1;
}

static void handle_ssl_error(int n, int r) {
	r = SSL_get_error(cons[n].s, r);
	if (r == SSL_ERROR_WANT_READ) {
		ev[n].events |= POLLIN;
	} else if (r == SSL_ERROR_WANT_WRITE) {
		ev[n].events |= POLLOUT;
	} else {
		if (cons[n].other) {
			int other = cons[n].other - cons;
			if (other < fd_count && cons[other].buf->len > 0)
				shutdown(ev[other].fd, SHUT_RD);
			else if (n < other)
				rm_conn(other);
		}
		rm_conn(n);
	}
	ERR_clear_error();
}

static int ssl_read(con c, int pf) {
	int ofs, n;
	buf buf = c->other->buf;
	char *p, *e;
	host h;

	ofs = buf->start + buf->len;
	if ((n = sizeof buf->data - 1 - ofs) < sizeof buf->data / 4) {
		if (c->other - cons >= fd_count)
			goto close;
		return 1;
	}
	if (!(pf & (POLLIN | POLLOUT))) {
		ev[c - cons].events |= POLLIN;
		return 1;
	}
	if ((n = SSL_read(c->s, buf->data + ofs, n)) <= 0) {
		handle_ssl_error(c - cons, n);
		return 0;
	}
	buf->len += n;
	if ((ofs = c->other - cons) < fd_count) {
		ev[ofs].events |= POLLOUT;
		return 1;
	}
	p = buf->data;
	p[buf->len] = 0;
	while ((p = strstr(p, "\r\n")) && strncasecmp(p += 2, "host:", 5))
		if (*p == '\r')
			goto close;
	if (!p || !*(p += 5, p += strspn(p, " ")) || !(e = strchr(p, '\r')))
		return 1;
	*e = 0;
	for (h = SSL_get_ex_data(c->s, host_idx); h; h = h->next) {
		if (!strcmp(h->name, p)) {
			*e = '\r';
			return forward(c, h);
		}
	}
close:
	rm_conn(c - cons);
	return 0;
}

static int ssl_write(con c) {
	int r = SSL_write(c->s, c->buf->data, c->buf->len);
	if (r > 0) {
		free(c->buf);
		c->buf = NULL;
		if (c->other)
			ev[c->other - cons].events |= POLLIN;
	} else {
		handle_ssl_error(c - cons, r);
	}
	return r;
}

static int ssl_accept() {
	con c, co;
	int fd, opt = 1;
	BIO *bio = NULL;

	if ((fd = accept(ev[0].fd, NULL, NULL)) < 0 ||
			!prepare_sock(fd, fd_count + 2 < fd_limit))
		return 0;
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof opt);
	setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &opt, sizeof opt);
	ev[fd_count].fd = fd;
	ev[fd_count].events = 0;
	c = cons + fd_count++;
	memset(c, 0, sizeof(struct con));
	c->other = co = cons + --fd_limit;
	co->other = c;
	co->s = NULL;
	if (!(co->buf = malloc(sizeof(struct buf))) ||
	    !(c->s = SSL_new(ctx)) ||
	    !(bio = BIO_new_socket(fd, 0))) {
		fputs("SSL error\n", stderr);
		rm_conn(fd_count - 1);
		return 0;
	}
	SSL_set_accept_state(c->s);
	SSL_set_bio(c->s, bio, bio);
	ERR_clear_error();
	co->buf->len = 0;
	co->buf->start = 0;
	ssl_read(c, POLLIN);
	return 1;
}

static int buf_read(int fd, con c) {
	int n;

	if (!c || c->buf)
		return 1;
	if (!(c->buf = malloc(sizeof(struct buf)))) {
		if (c < c->other)
			rm_conn(c->other - cons);
		return 0;
	}
	n = read(fd, c->buf->data, sizeof c->buf->data);
	if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
		free(c->buf);
		c->buf = NULL;
	} else if (n <= 0) {
		return 0;
	} else {
		c->buf->len = n;
		ssl_write(c);
	}
	return 1;
}

static int buf_write(int fd, buf buf, con other) {
	int n;

	if (buf->len <= 0)
		return 1;
	if ((n = write(fd, buf->data + buf->start, buf->len)) < 0)
		return errno == EINTR || errno == EAGAIN;
	if ((buf->len -= n) > 0) {
		buf->start += n;
	} else {
		buf->start = 0;
		if (other)
			ev[other - cons].events |= POLLIN;
	}
		
	return 1;
}

static void after_poll() {
	int i;

	for (i = fd_count; --i > 0; ) {
		con c = cons + i;

		if ((ev[i].revents & (POLLHUP | POLLERR))) {
			rm_conn(i);
			// TODO check socket errors from connect
			// TODO do nice SSL shutdown?
			continue;
		}
		ev[i].events = POLLHUP | POLLERR;
		if (c->s) {
			if ((ev[i].revents & (POLLIN | POLLOUT)) &&
			    	c->buf && ssl_write(c) <= 0 ||
			     c->other && !ssl_read(c, ev[i].revents))
				continue;
			if (c->other) {
				struct buf *b = c->other->buf;
				if (b->start + b->len < sizeof b->data)
					ev[i].events |= POLLIN;
			}
		} else if ((ev[i].revents & POLLOUT) &&
				!buf_write(ev[i].fd, c->buf, c->other) ||
		           (ev[i].revents & POLLIN) &&
				!buf_read(ev[i].fd, c->other)) {
			rm_conn(i);
			continue;
		} else if (c->other && !c->other->buf) {
			ev[i].events |= POLLIN;
		}
		if (c->buf && c->buf->len >= 0)
			ev[i].events |= POLLOUT;
		else if (!c->other)
			rm_conn(i);
	}
	if ((ev[0].revents & POLLIN))
		ssl_accept();
	ev[0].events = fd_count < MAX_FDS ? POLLIN : 0;
}

static void listen_sock(int port) {
	struct sockaddr_in sa;
	int fd, v = 1;

	expect((fd = socket(PF_INET, SOCK_STREAM, IPPROTO_IP)) >= 0);
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof v);
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (bind(fd, (struct sockaddr*) &sa, sizeof sa)) {
		fprintf(stderr, "bind %d: %s\n", port, strerror(errno));
		exit(1);
	}
	expect(!listen(fd, 64));
	ev[0].fd = fd;
	ev[0].events = POLLIN;
	fd_count = 1;
}

int main() {
	init_context();
	if (!load_conf("https.conf"))
		return 1;
	listen_sock(server_port);
	for (;;) {
		if (poll(ev, fd_count, -1) > 0) {
			after_poll();
		} else if (errno != EINTR) {
			perror("poll");
			break;
		}
	}
	free_context();
	return 0;
}
