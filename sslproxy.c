#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <poll.h>
#include <alloca.h>

#define MAX_FDS 512
#define expect(v) if (!(v)) { fputs("** ERROR " #v "\n", stderr); exit(1); }

void OPENSSL_cpuid_setup();
void RAND_cleanup();

struct buf {
	int len;
	int start;
	char data[16384];
};

struct con {
	SSL *s;
	struct buf *buf;
	struct con *other;
};

static SSL_CTX *ctx;
static struct pollfd ev[MAX_FDS];
static struct con cons[MAX_FDS];
static int fd_count;
static int fd_limit = MAX_FDS;

static void rm_conn(int n) {
	struct con *c = cons + n;

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
	unsigned len;
	unsigned char *md;
	const EVP_MD *alg = EVP_sha256();

	if (!(len = EVP_MD_size(alg)) || !(md = alloca(len)) ||
	    !X509_digest(s->cert, alg, md, &len)) {
		s->error = X509_V_ERR_APPLICATION_VERIFICATION;
		return 0;
	}
	//s->error = X509_V_ERR_CERT_REJECTED;
	//return 0;
	fputs("Verify done\n", stderr);
	return 1;
}

static void init_context() {
	SSL_library_init();
	ERR_load_crypto_strings();
	OPENSSL_cpuid_setup();
	EVP_add_cipher(EVP_aes_128_cbc());
	EVP_add_cipher(EVP_aes_192_cbc());
	EVP_add_cipher(EVP_aes_256_cbc());
	EVP_add_digest(EVP_sha1());
	EVP_add_digest(EVP_sha224());
	EVP_add_digest(EVP_sha256());
	signal(SIGPIPE, SIG_IGN);

	expect(ctx = SSL_CTX_new(TLSv1_server_method()));
	SSL_CTX_set_cert_verify_callback(ctx, verify, NULL);
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
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

static void free_context() {
	ERR_free_strings();
	ERR_remove_state(0);
	RAND_cleanup();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
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

static int ssl_read(struct con *c, int pf) {
	int ofs, n;
	char *p, *e;
	struct buf *buf = c->other->buf;

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
	fprintf(stderr, "HOST=[%s]\n", p);
	return 1;
close:
	rm_conn(c - cons);
	return 0;
}

static int ssl_write(struct con *c) {
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
	struct con *c, *co;
	int fd;
	BIO *bio = NULL;

	if ((fd = accept(ev[0].fd, NULL, NULL)) < 0) {
		return 0;
	}
	if (fd_count + 2 >= fd_limit || fcntl(fd, F_SETFL, (long) O_NONBLOCK)) {
		close(fd);
		return 0;
	}
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
	SSL_set_verify(c->s, SSL_VERIFY_PEER |
	                     SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	SSL_set_bio(c->s, bio, bio);
	ERR_clear_error();
	co->buf->len = 0;
	co->buf->start = 0;
	ssl_read(c, POLLIN);
	return 1;
}

static int buf_read(int fd, struct con *c) {
	int n;

	if (!c || c->buf)
		return 1;
	if (!(c->buf = malloc(sizeof(c->buf)))) {
		if (c < c->other)
			rm_conn(c->other - cons);
		return 0;
	}
	n = read(fd, c->buf->data, sizeof c->buf->data);
	if (n < 0 && (errno == EINTR || errno == EAGAIN ||
		      errno == EWOULDBLOCK)) {
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

static int buf_write(int fd, struct buf *buf, struct con *other) {
	int n;

	if (buf->len <= 0)
		return 1;
	if ((n = write(fd, buf->data + buf->start, buf->len)) < 0) {
		return errno == EINTR || errno == EAGAIN ||
		       errno == EWOULDBLOCK;
	}
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
		struct con *c = cons + i;

		if ((ev[i].revents & (POLLHUP | POLLERR))) {
			rm_conn(i);
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
		} else if (c->other && !c->other->buf)
			ev[i].events |= POLLIN;
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
	if (!load_keycert("ssl.pem")) {
		return 1;
	}
	listen_sock(4443);
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
