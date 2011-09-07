#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <stdio.h>
#include <poll.h>
#include <alloca.h>

#define MAX_FD 512
#define expect(v) if (!(v)) { fputs("** ERROR " #v "\n", stderr); exit(1); }

struct buf {
	int len;
	char data[16384];
};

struct con {
	SSL *s;
	struct buf *sbuf, *nbuf;
};

static SSL_CTX *ctx;
struct pollfd ev[MAX_FD + 1];
struct con cons[MAX_FD + 1];

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

int accept(int sfd) {
	int fd;
	SSL *s;

	if ((fd = accept(sfd, NULL, NULL)) < 0) {
		return 0;
	}
	expect(s = SSL_new(ctx));

}

int main() {
	init_context();
	if (!load_keycert("ssl.pem")) {
		return 1;
	}

	free_context();
	return 0;
}
