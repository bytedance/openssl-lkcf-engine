#include "lkcf.h"

#include <errno.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "log.h"
#include "e_lkcf_err.h"

#ifndef gettid
#define gettid() syscall(SYS_gettid)
#endif

#define KEY_TAG_RSA_PKEY "rsa:pkey"

static key_serial_t lkcf_dummy_payload = INVALID_KEYCTL_ID;

static char *lkcf_build_desc(char *buffer, size_t len, const char *tag)
{
	static __thread uint64_t idx = 0;
	snprintf(buffer, len, "e_lkcf-%s-%ld-%ld", tag, gettid(), idx++);
	return buffer;
}

int lkcf_pkey_add(PkeyExCtx *pkey_ctx,
                  const unsigned char *payload,
                  size_t payload_len) {
	/* currently only rsa supported */
	lkcf_build_desc(pkey_ctx->desc, sizeof(pkey_ctx->desc), KEY_TAG_RSA_PKEY);
	pkey_ctx->id = add_key(KEY_TYPE_PKEY, pkey_ctx->desc, payload, payload_len, KEY_SPEC_PROCESS_KEYRING);
	if (pkey_ctx->id == INVALID_KEYCTL_ID) {
		log_error("Failed to add pkey: %d", errno);
		LKCFerr(LKCF_F_LKCF_PKEY_ADD, LKCF_R_LKCF_INVALID_PAYLOAD);
	}

	return pkey_ctx->id == INVALID_KEYCTL_ID ? 0 : 1;
}

int lkcf_init()
{
	int ret;
	char payload[] = "e_lkcf_init:force create keyring";

	ret = add_key("user", "e_lkcf_init", payload, sizeof(payload), KEY_SPEC_PROCESS_KEYRING);
	if (ret < 0) {
		log_error("Failed to upload user param to keyring: %d", errno);
		LKCFerr(LKCF_F_LKCF_INIT, LKCF_R_KEYCTL_ADD_FAILURE);
		return 0;
	}

	lkcf_dummy_payload = ret;
	return 1;
}

int lkcf_destroy()
{
	if (lkcf_dummy_payload != INVALID_KEYCTL_ID) {
		return lkcf_unlink_key(lkcf_dummy_payload) == 0;
	}

	return 1;
}

int lkcf_upload_rsa_privkey(PkeyExCtx *pkey_ctx,
                            RSA *rsa)
{
	int ret = 0, payload_len;
	unsigned char *payload = NULL;
	EVP_PKEY *pkey = NULL;
	PKCS8_PRIV_KEY_INFO *p8info = NULL;

	if (lkcf_pkey_error(pkey_ctx) ||
	    !lkcf_pkey_uninitialized(pkey_ctx)) {
		return ret;
	}
	if (!RSA_check_key(rsa)) {
		log_error("Invalid RSA key");
		LKCFerr(LKCF_F_LKCF_UPLOAD_RSA_PRIVKEY, LKCF_R_INVALID_RSA_KEY);
		return ret;
	}
	
	pkey = EVP_PKEY_new();
	if (!pkey || EVP_PKEY_set1_RSA(pkey, rsa) <= 0) {
		log_error("Failed to initialize pkey");
		goto clear;
	}
	p8info = EVP_PKEY2PKCS8(pkey);
	if (!p8info ||
		(payload_len = i2d_PKCS8_PRIV_KEY_INFO(p8info, &payload)) <= 0) {
		log_error("Failed to export pkey to pkcs8");
		goto clear;
	}

	ret = lkcf_pkey_add(pkey_ctx, payload, payload_len);

clear:
	OPENSSL_free(payload);
	PKCS8_PRIV_KEY_INFO_free(p8info);
	EVP_PKEY_free(pkey);
	return ret;
}
