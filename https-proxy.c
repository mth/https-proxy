#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <syslog.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <pwd.h>

#define MAX_FDS 512
#define expect(v) if (!(v)) { fputs("** ERROR " #v "\n", stderr); exit(1); }
#define SHA256_LEN 32

void OPENSSL_cpuid_setup();
void RAND_cleanup();

typedef struct con {
	int idx;
	SSL *s;
	struct con *other;
	int len;
	int start;
	char data[16384];
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
static con cons[MAX_FDS];
static int fd_count;
static int server_port = 443;
static int tls_only;
static int host_idx;
static uid_t use_uid;
static digest digests;

static void rm_conn(con c) {
	int n;

	if (!c)
		return;
	if (c->other) {
		c->other->other = NULL;
		if (!c->other->idx)
			rm_conn(c->other);
	}
	if ((n = c->idx)) {
		SSL_free(c->s);
		close(ev[n].fd);
		ev[n] = ev[--fd_count];
		(cons[n] = cons[fd_count])->idx = n;
	}
	free(c);
	cons[fd_count] = NULL;
}

static int check_cert(X509 *cert, host *hosts) {
	digest i;
	unsigned char md[SHA256_LEN];
	unsigned len = sizeof md;
	const EVP_MD *alg = EVP_sha256();

	if (!cert) {
		syslog(LOG_ERR, "No peer certificate");
		return X509_V_ERR_APPLICATION_VERIFICATION;
	}
	if (EVP_MD_size(alg) != len || !X509_digest(cert, alg, md, &len)) {
		syslog(LOG_ERR, "No verify digest available");
		return X509_V_ERR_APPLICATION_VERIFICATION;
	}
	ERR_clear_error();
	for (i = digests; i; i = i->next) {
		if (!memcmp(i->value, md, sizeof md)) {
			while (i && !i->hosts)
				i = i->next;
			*hosts = i ? i->hosts : NULL;
			return X509_V_OK;
		}
	}
	syslog(LOG_INFO | LOG_AUTHPRIV, "Unknown client certificate rejected");
	return  X509_V_ERR_CERT_REJECTED;
}

static int verify(X509_STORE_CTX *s, void *arg) {
	host h = NULL;
	SSL *ssl;
	int result;

	s->error = X509_V_ERR_APPLICATION_VERIFICATION;
	if (!(ssl = X509_STORE_CTX_get_app_data(s))) {
		syslog(LOG_ERR, "Cannot get SSL object in verify callback");
		return 0;
	}
	result = check_cert(s->cert, &h);
	if (h && !SSL_set_ex_data(ssl, host_idx, h)) {
		syslog(LOG_ERR, "SSL_set_ex_data failed");
		return 0;
	}
	s->error = result;
	return result == X509_V_OK;
}

static void init_context() {
	char sess_ctx[SSL_MAX_SSL_SESSION_ID_LENGTH];

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
	if (tls_only) {
		expect(ctx = SSL_CTX_new(TLSv1_server_method()));
	} else {
		expect(ctx = SSL_CTX_new(SSLv23_server_method()));
		SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
	}
	SSL_CTX_set_cert_verify_callback(ctx, verify, NULL);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |
	                   SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	strcpy(sess_ctx, "HsP-");
	gethostname(sess_ctx + 4, sizeof sess_ctx - 4);
	SSL_CTX_set_session_id_context(ctx, (unsigned char*) sess_ctx,
	                               strlen(sess_ctx));
	//SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
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
	digest to;
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
	for (to = digests; !to->hosts && to->next; to = to->next);
	h->next = to->hosts;
	to->hosts = h;
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
		} else if (!strcmp(what, "user")) {
			struct passwd *pw = getpwnam(buf);
			if (!pw) {
				fprintf(stderr, "%s: no user %s\n", fn, buf);
			} else {
				use_uid = pw->pw_uid;
				setgid(pw->pw_gid);
			}
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

static void handle_ssl_error(con c, int r) {
	r = SSL_get_error(c->s, r);

	if (r == SSL_ERROR_WANT_READ) {
		ev[c->idx].events |= POLLIN;
	} else if (r == SSL_ERROR_WANT_WRITE) {
		ev[c->idx].events |= POLLOUT;
	} else {
		ERR_print_errors_fp(stderr);
		if (c->other) {
			if (c->other->idx && c->other->len > 0)
				shutdown(ev[c->other->idx].fd, SHUT_RD);
			else
				rm_conn(c->other);
		}
		rm_conn(c);
	}
	ERR_clear_error();
}

static int closereq(con c) {
	int r;

	if (c->other && c->other->len <= 0) {
		c->len = 0;
		if (!c->s)
			return closereq(c->other);
		rm_conn(c->other);
	}
	ERR_clear_error();
	if (!c->s || (r = SSL_shutdown(c->s)) > 0) {
		rm_conn(c);
	} else {
		c->start = -1;
		handle_ssl_error(c, r);
	}
	return 0;
}

static int forward(con c, host h) {
	int fd;

	if (fd_count >= MAX_FDS ||
	    (fd = socket(h->ai->ai_family, h->ai->ai_socktype, h->ai->ai_protocol))
			< 0 || !prepare_sock(fd, 1))
		return closereq(c);

	if (connect(fd, h->ai->ai_addr, h->ai->ai_addrlen) &&
			errno != EINPROGRESS) {
		close(fd);
		return closereq(c);
	}

	ev[fd_count].fd = fd;
	ev[fd_count].events = POLLOUT;
	c->other->idx = fd_count;
	cons[fd_count++] = c->other;
	return 1;
}

static int check_host(con c, char *p) {
	char *e;
	host h;

	while ((p = strstr(p, "\r\n")) && strncasecmp(p += 2, "host:", 5)) {
		if (*p == '\r') {
			syslog(LOG_INFO, "Cannot determine host");
			return closereq(c);
		}
	}
	if (!p || !*(p += 5, p += strspn(p, " ")) || !(e = strchr(p, '\r')))
		return 1;
	*e = 0;
	if (!(h = SSL_get_ex_data(c->s, host_idx)))
	    check_cert(SSL_get_peer_certificate(c->s), &h);
	if (!h) {
		syslog(LOG_INFO, "No hosts when checking %s", p);
		return closereq(c);
	}
	for (; h; h = h->next) {
		if (!strcmp(h->name, p)) {
			*e = '\r';
			return forward(c, h);
		}
	}
	syslog(LOG_INFO, "Unknown host (%s)", p);
	return closereq(c);
}

static int ssl_read(con c, int pf) {
	int ofs, n;
	con buf = c->other;

	ofs = buf->start + buf->len;
	if ((n = sizeof buf->data - 1 - ofs) < sizeof buf->data / 4)
		return buf->idx ? 1 : closereq(c);
	if (!(pf & (POLLIN | POLLOUT))) {
		ev[c->idx].events |= POLLIN;
		return 1;
	}
	ERR_clear_error();
	if ((n = SSL_read(c->s, buf->data + ofs, n)) <= 0) {
		handle_ssl_error(c, n);
		return 0;
	}
	buf->len += n;
	if (!buf->idx) {
		buf->data[buf->len] = 0;
		return check_host(c, buf->data);
	}
	ev[buf->idx].events |= POLLOUT;
	return 1;
}

static int ssl_write(con c) {
	ERR_clear_error();
	int r = SSL_write(c->s, c->data, c->len);
	if (r <= 0) {
		handle_ssl_error(c, r);
		return 0;
	}
	c->start = 0;
	c->len = 0;
	if (c->other)
		ev[c->other->idx].events |= POLLIN;
	return 1;
}

static inline con new_con() {
	con c = malloc(sizeof(struct con));
	if (c)
		memset(c, 0, sizeof(struct con) - sizeof c->data);
	return c;
}

static int ssl_accept() {
	con c = NULL;
	int fd;
	BIO *bio;

	if ((fd = accept(ev[0].fd, NULL, NULL)) < 0 ||
			!prepare_sock(fd, (c = new_con()) != NULL)) {
		free(c);
		return 0;
	}
	ev[fd_count].fd = fd;
	ev[fd_count].events = 0;
	if (!(c->other = new_con()) ||
	    !(c->s = SSL_new(ctx)) ||
	    !(bio = BIO_new_socket(fd, 0))) {
		syslog(LOG_ERR, "Out of memory");
		rm_conn(c);
		return 0;
	}
	cons[fd_count] = c;
	c->idx = fd_count++;
	c->other->other = c;
	SSL_set_accept_state(c->s);
	SSL_set_bio(c->s, bio, bio);
	ERR_clear_error();
	ssl_read(c, POLLIN);
	return 1;
}

static int buf_read(int fd, con c) {
	if (c && c->len <= 0) {
		int n = read(fd, c->data, sizeof c->data);
		if (n > 0) {
			c->len = n;
			ssl_write(c);
		} else if (!n || errno != EINTR && errno != EAGAIN) {
			return 0;
		}
	}
	return 1;
}

static int buf_write(int fd, con buf) {
	int n;

	if (buf->len <= 0)
		return 1;
	if ((n = write(fd, buf->data + buf->start, buf->len)) < 0)
		return errno == EINTR || errno == EAGAIN;
	if ((buf->len -= n) > 0) {
		buf->start += n;
	} else {
		buf->start = 0;
		if (buf->other)
			ev[buf->other->idx].events |= POLLIN;
	}
	return 1;
}

static void after_poll() {
	int i;

	for (i = fd_count; --i > 0; ) {
		con c = cons[i];

		if (!c)
			continue;
		if ((ev[i].revents & (POLLHUP | POLLERR))) {
			rm_conn(c);
			// TODO check socket errors from connect
			// TODO do nice SSL shutdown?
			continue;
		}
		ev[i].events = POLLHUP | POLLERR;
		if (c->s) {
			if ((ev[i].revents & (POLLIN | POLLOUT)) &&
			    c->start < 0 && !closereq(c) ||
			    c->len > 0 && ssl_write(c) <= 0 ||
			    c->other && !ssl_read(c, ev[i].revents))
				continue;
			if (c->other && c->other->start + c->other->len
			                   < sizeof c->other->data)
				ev[i].events |= POLLIN;
		} else if ((ev[i].revents & POLLOUT) && !buf_write(ev[i].fd, c) ||
		           (ev[i].revents & POLLIN) && !buf_read(ev[i].fd, c->other)) {
			closereq(c);
			continue;
		} else if (c->other && c->other->len <= 0) {
			ev[i].events |= POLLIN;
		}
		if (c->len > 0)
			ev[i].events |= POLLOUT;
		else if (!c->other)
			closereq(c);
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

static int help() {
	puts("\nhttps-proxy [options]\n\n"
	     "\t-c config  Configuration file to use\n"
	     "\t-h         Print this help\n"
	     "\t-t         Allow only TLSv1 (no SSL)\n");
	return 0;
}

int main(int argc, char **argv) {
	int i;
	const char *cfg = "/etc/https/proxy.conf";;

	for (i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "-c") && ++i < argc)
			cfg = argv[i];
		else if (!strcmp(argv[i], "-t"))
			tls_only = 1;
		else if (!strcmp(argv[i], "-h"))
			return help();
	}

	init_context();
	if (!load_conf(cfg))
		return 1;
	listen_sock(server_port);
	if (use_uid && setuid(use_uid)) {
		fprintf(stderr, "setuid(%d): %s\n", use_uid, strerror(errno));
		return 1;
	}
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
