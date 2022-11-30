#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <keyutils.h>

#include "log.h"

#define ENGINE_ID "lkcf-engine"

#define ERR_BUF_SIZE 256
#define BUFFER_SIZE 4096

typedef char SSL_err_buff[ERR_BUF_SIZE];
typedef const EVP_MD* EVP_MD_PTR;

static char * ssl_err(char *buffer) 
{
	ERR_error_string_n(ERR_get_error(), buffer, ERR_BUF_SIZE);
	return buffer;
}

static int dump_factor(const RSA *from, RSA *to)
{
	const BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

	RSA_get0_key(from, &n, &e, &d);
	RSA_get0_factors(from, &p, &q);
	RSA_get0_crt_params(from, &dmp1, &dmq1, &iqmp);
	if (RSA_set0_key(to, BN_dup(n), BN_dup(e), BN_dup(d)) != 1 ||
		RSA_set0_factors(to, BN_dup(p), BN_dup(q)) != 1 ||
		RSA_set0_crt_params(to, BN_dup(dmp1), BN_dup(dmq1), BN_dup(iqmp)) != 1) {
		log_error("Failed to get params");
		return -1;
	}
	return 0;
}

static RSA* gen_rsa(ENGINE *engine, int bits)
{
	RSA *r = NULL;
	BIGNUM *bne = NULL;
	unsigned long e = RSA_F4;
	SSL_err_buff err;

	// 1. generate rsa key
	bne = BN_new();
	if(!bne || BN_set_word(bne, e) != 1){
		log_error("Failed set e: %s", ssl_err(err));
		goto clear;
	}

	r = RSA_new_method(engine);
	if (!r || RSA_generate_key_ex(r, bits, bne, NULL) != 1) {
		log_error("Failed to generate key: %s", ssl_err(err));
		goto clear;
	}
	log_error("Gerenarted rsa key, bits: %d", bits);
	goto out;

clear:
	RSA_free(r);
out:
	BN_free(bne);
	return r;
}

static int compute_digest(const EVP_MD *md,
	                      const char *msg, 
	                      size_t mlen,
	                      unsigned char* digest)
{
	EVP_MD_CTX *mdctx;
	unsigned int md_len;

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, msg, mlen);
	EVP_DigestFinal_ex(mdctx, digest, &md_len);
	EVP_MD_CTX_free(mdctx);
	return md_len;
}

static void randstr(char *buf, int buf_len)
{
	int i,j;
	
	for (i = 0; i < buf_len; i++) {
		j = rand() % 52;
		if (j < 26) {
			buf[i] = (char)('a' + j);
		} else {
			buf[i] = (char)('A' + j - 26);
		}
	}
}

static bool test_rsa_impl(RSA *rsa, RSA* rsa_builtin, int padding, const EVP_MD *md)
{
	bool passed = false;
	int rsa_len = RSA_size(rsa), msg_len, dgst_len = EVP_MD_size(md);
	unsigned int sig_len; 
	unsigned char *message = OPENSSL_malloc(rsa_len); 
	unsigned char *secret = OPENSSL_malloc(rsa_len); 
	unsigned char *buffer = OPENSSL_malloc(rsa_len);
	unsigned char *sig = OPENSSL_malloc(rsa_len); 
	unsigned char *dgst = OPENSSL_malloc(dgst_len);
	char hex_buf[BUFFER_SIZE];
	SSL_err_buff err;
	(void)hex_buf;

	ERR_clear_error();
	randstr((char *)message, rsa_len);

	if (padding == RSA_NO_PADDING) {
		msg_len = rsa_len;
		message[0] &= 0x7F;
	} else {
		msg_len = rsa_len / 2;
	}

	if (RSA_public_encrypt(msg_len, message, secret, rsa, padding) != rsa_len) {
		log_error("Failed to encrypt message with public key: %s", ssl_err(err));
		goto clear;
	}
	if (RSA_private_decrypt(rsa_len, secret, buffer, rsa, padding) != msg_len || 
		memcmp(buffer, message, msg_len) != 0) {
		log_error("Failed to decrypt secret with private key: %s", ssl_err(err));
		goto clear;
	}
	if (RSA_private_decrypt(rsa_len, secret, buffer, rsa_builtin, padding) != msg_len || 
		memcmp(buffer, message, msg_len) != 0) {
		log_error("Failed to decrypt secret with private key: %s", ssl_err(err));
		goto clear;
	}

	if (padding == RSA_PKCS1_OAEP_PADDING) {
		goto sign_test;
	}
	if (RSA_private_encrypt(msg_len, message, secret, rsa, padding) != rsa_len) {
		log_error("Failed to encrypt message with private key: %s", ssl_err(err));
		goto clear;
	}
	if (RSA_public_decrypt(rsa_len, secret, buffer, rsa, padding) != msg_len || 
		memcmp(buffer, message, msg_len) != 0) {
		log_error("Failed to decrypt message with public key: %s", ssl_err(err));
		goto clear;
	}
	if (RSA_public_decrypt(rsa_len, secret, buffer, rsa_builtin, padding) != msg_len || 
		memcmp(buffer, message, msg_len) != 0) {
		log_error("Failed to decrypt message with public key: %s", ssl_err(err));
		goto clear;
	}

	if (padding == RSA_NO_PADDING) {
		passed = true;
		goto clear;
	}

sign_test:
	if (compute_digest(md, (char*)message, msg_len, dgst) != dgst_len) {
		log_error("Failed to compute message digest: %s", ssl_err(err));
		goto clear;
	}

	if (RSA_sign(EVP_MD_type(md), dgst, dgst_len, sig, &sig_len, rsa) != 1 ||
		sig_len != rsa_len)
	{
		log_error("Failed to make signature, %s", ssl_err(err));
		goto clear;
	}


	if (RSA_verify(EVP_MD_type(md), dgst, dgst_len, sig, rsa_len, rsa) != 1) {
		log_error("Failed to verify signature, %s", ssl_err(err));
		goto clear;
	}
	if (RSA_verify(EVP_MD_type(md), dgst, dgst_len, sig, rsa_len, rsa_builtin) != 1) {
		log_error("Failed to verify signature, %s", ssl_err(err));
		goto clear;
	}
	sig[0]++;
	if (RSA_verify(EVP_MD_type(md), dgst, dgst_len, sig, rsa_len, rsa) != 0) {
		log_error("Failed to verify signature, %s", ssl_err(err));
		goto clear;
	}
	sig[0]--;
	passed = true;

clear:
	OPENSSL_free(message);
	OPENSSL_free(secret);
	OPENSSL_free(buffer);
	OPENSSL_free(sig);
	OPENSSL_free(dgst);
	return passed;
}

static void test_rsa(ENGINE *e)
{
	RSA *rsa = gen_rsa(e, 2048);
	RSA *rsa_builtin = RSA_new();
	dump_factor(rsa, rsa_builtin);

	int paddings[] = { RSA_NO_PADDING, RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING };
	EVP_MD_PTR mds[] = { EVP_md5(), EVP_sha1(), EVP_sha384(), EVP_sha256(), EVP_sha512() };

	for (int i = 0; i < sizeof(paddings) / sizeof(int); i++) {
		for (int j = 0; j < sizeof(mds) / sizeof(EVP_MD_PTR); j++) {
			log_error("rsa test, padding: %d, md type: %d", paddings[i], EVP_MD_type(mds[j]));
			if (!test_rsa_impl(rsa, rsa_builtin, paddings[i], mds[j])) {
				log_error("Failed to test rsa implement, padding: %d, md: %d, i:%d, j:%d",
					paddings[i], EVP_MD_type(mds[j]), i, j);
			}
		}
	}

	RSA_free(rsa);
	RSA_free(rsa_builtin);
}

static DH *gen_dh_secret(ENGINE *e, int len) 
{
	log_error("gerenate dh key...");
	SSL_err_buff err;
	DH *dh = DH_new_method(e);
	if (!dh) {
		log_error("Failed to create dh method");
		goto err;
	}
	if (DH_generate_parameters_ex(dh, len, DH_GENERATOR_2, NULL) != 1) {
		log_error("Failed to generate private key and public key, %s", ssl_err(err));
		goto err;
	}

	return dh;
err:
	DH_free(dh);
	return NULL;
}

static void test_dh(ENGINE *e) 
{
	DH *dh1, *dh2;
	const BIGNUM *pub1, *pub2;
	const BIGNUM *p, *g, *q;
	unsigned char *key1 = NULL, *key2 = NULL;
	const int len = 2048;
	SSL_err_buff err;

	ERR_clear_error();
	dh1 = gen_dh_secret(e, len);
	dh2 = DH_new_method(NULL);
	if (!dh1 || !dh2) {
		log_error("Failed to gen dh secret");
		goto clear;
	}

	// share common parameters 
	DH_get0_pqg(dh1, &p, &q, &g);
	DH_set0_pqg(dh2, BN_dup(p), BN_dup(q), BN_dup(g));
	key1 = OPENSSL_malloc(len / sizeof(unsigned char));
	key2 = OPENSSL_malloc(len / sizeof(unsigned char));
	if (!DH_generate_key(dh1)) {
		log_error("Failed to generate key with "ENGINE_ID" algorithm, %s", ssl_err(err));
		goto clear;
	}
	if (!DH_generate_key(dh2)) {
		log_error("Failed to generate key with "ENGINE_ID" %s", ssl_err(err));
		goto clear;
	}
	pub1 = DH_get0_pub_key(dh1);
	pub2 = DH_get0_pub_key(dh2);

	int ret;
	ret = DH_compute_key(key1, pub2, dh1);
	if (ret <= 0) {
		log_error("Failed to generate key with builtin algorithm, %s", ssl_err(err));
		goto clear;
	}
	ret = DH_compute_key(key2, pub1, dh2);
	if(ret <= 0) {
		log_error("Failed to generate key with "ENGINE_ID", %s", ssl_err(err));
		goto clear;
	}
	if (memcmp(key1, key2, len / 8) != 0) {
		log_error("The exchanged keys doesn't match");
		goto clear;
	}

clear:
	OPENSSL_free(key1);
	OPENSSL_free(key2);
	DH_free(dh1);
	DH_free(dh2);
}

int main(int argc, char** argv) 
{
	ENGINE *e;
	ENGINE_load_dynamic();
	if (!(e = ENGINE_by_id(ENGINE_ID))) {
		log_error("failed to find engine");
		return -1;
	}
	log_error("Loaded: (%s) %s", ENGINE_get_id(e), ENGINE_get_name(e));
	const DH_METHOD *dh;
	if (ENGINE_get_RSA(e) != NULL) {
		log_error("RSA supported");
		test_rsa(e);
	}

	if ((dh = ENGINE_get_DH(e)) != NULL) {
			if (0) {

		test_dh(e);
			}
	}

	return 0;
}
