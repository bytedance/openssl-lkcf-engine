#include "lkcf_rsa.h"

#include <string.h>
#include <errno.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "e_lkcf_err.h"
#include "log.h"
#include "lkcf.h"

static RSA_METHOD *lkcf_rsa_meth = NULL;
static const RSA_METHOD *ossl_rsa_meth = NULL;
static int lkcf_rsa_idx = 0;

/* lkcf engine RSA methods declaration */
static int lkcf_rsa_priv_enc(int flen, const unsigned char *from,
                             unsigned char *to, RSA *rsa, int padding);
static int lkcf_rsa_priv_dec(int flen, const unsigned char *from,
                             unsigned char *to, RSA *rsa, int padding);
static int lkcf_rsa_pub_enc(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding);
static int lkcf_rsa_pub_dec(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding);

static void lkcf_pkey_ex_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
				             int idx, long argl, void *argp) 
{
	PkeyExCtx *pkey_ctx = lkcf_pkey_ctx_new();
	CRYPTO_set_ex_data(ad, idx, pkey_ctx);
}

static int lkcf_pkey_ex_dup(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
				            void *from_d, int idx, long argl, void *argp) 
{
	PkeyExCtx *dst_pkey = lkcf_pkey_ctx_new();
	*(PkeyExCtx **)from_d = dst_pkey;
	return 0;
}

static void lkcf_pkey_ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
				       int idx, long argl, void *argp)
{
	PkeyExCtx *pkey = (PkeyExCtx *)ptr;
	lkcf_pkey_ctx_free(pkey);
}

RSA_METHOD *lkcf_get_RSA_methods(void)
{
	int res = 1;
	if (lkcf_rsa_meth) {
		return lkcf_rsa_meth;
	}

	if (!ossl_rsa_meth) {
		ossl_rsa_meth = RSA_PKCS1_OpenSSL();
		if (!ossl_rsa_meth) {
			return NULL;
		}
	}

	lkcf_rsa_meth = RSA_meth_dup(ossl_rsa_meth);
	if (lkcf_rsa_meth == NULL) {
		log_error("Failed to alloc lkcf rsa method");
		return NULL;
	}

	lkcf_rsa_idx = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, 0, NULL, 
	                                       lkcf_pkey_ex_new,
										   lkcf_pkey_ex_dup,
										   lkcf_pkey_ex_free);

	res &= RSA_meth_set1_name(lkcf_rsa_meth, "lkcf rsa meth");
	res &= RSA_meth_set_pub_enc(lkcf_rsa_meth, lkcf_rsa_pub_enc);
	res &= RSA_meth_set_pub_dec(lkcf_rsa_meth, lkcf_rsa_pub_dec);
	res &= RSA_meth_set_priv_enc(lkcf_rsa_meth, lkcf_rsa_priv_enc);
	res &= RSA_meth_set_priv_dec(lkcf_rsa_meth, lkcf_rsa_priv_dec);

	if (lkcf_rsa_idx < 0 || res == 0) {
		log_error("Failed to init lkcf rsa method, fallback to default rsa method");
		return (RSA_METHOD *)RSA_get_default_method();
	}

	return lkcf_rsa_meth;
}

void lkcf_free_RSA_methods(void)
{
	if (lkcf_rsa_meth) {
		RSA_meth_free(lkcf_rsa_meth);
		lkcf_rsa_meth = NULL;
	}
	if (lkcf_rsa_idx > 0 && 
		!CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA, lkcf_rsa_idx)) {
		log_error("Failed to free rsa lkcf_rsa_idx");
	}
}

static PkeyExCtx* lkcf_get_pkey_ctx(RSA *rsa) {
	PkeyExCtx *pkey_ctx = (PkeyExCtx *) RSA_get_ex_data(rsa, lkcf_rsa_idx);

	/* Unlikely to happen */
	if (!pkey_ctx) {
		return NULL;
	}

	if (lkcf_pkey_uninitialized(pkey_ctx)) {
		lkcf_upload_rsa_privkey(pkey_ctx, rsa);
	}
	return lkcf_pkey_ready(pkey_ctx) ? pkey_ctx : NULL;
}

static int lkcf_hw_rsa_pub_func(PkeyExCtx *pkey_ctx,
	                            const unsigned char *from, int flen,
	                            unsigned char *to, int tlen)
{
	int ret = keyctl_pkey_encrypt(pkey_ctx->id, "enc=raw", from, flen, to, tlen);

	if (ret <= 0) {
		switch (errno) {
		case ENOKEY:
			LKCFerr(LKCF_F_LKCF_HW_RSA_PUB_FUNC, LKCF_R_ENOKEY);	
			break;

		case EKEYEXPIRED:
			LKCFerr(LKCF_F_LKCF_HW_RSA_PUB_FUNC, LKCF_R_EKEYEXPIRED);	
			break;

		case EACCES:
			LKCFerr(LKCF_F_LKCF_HW_RSA_PUB_FUNC, LKCF_R_EACCES);	
			break;
			
		case ENOPKG:
			LKCFerr(LKCF_F_LKCF_HW_RSA_PUB_FUNC, LKCF_R_ENOPKG);	
			break;

		case EFAULT:
			LKCFerr(LKCF_F_LKCF_HW_RSA_PUB_FUNC, LKCF_R_EFAULT);;
			break;

		default:
			LKCFerr(LKCF_F_LKCF_HW_RSA_PUB_FUNC, LKCF_R_PKEY_ENCRYPT_ERR);
			break;
		}
	}
	return ret;
}

static int lkcf_hw_rsa_priv_func(PkeyExCtx *pkey_ctx,
	                             const unsigned char *from, int flen,
	                             unsigned char *to, int tlen)
{
	int ret = keyctl_pkey_decrypt(pkey_ctx->id, "enc=raw", from, flen, to, tlen);

	if (ret <= 0) {
		switch (errno) {
		case ENOKEY:
			LKCFerr(LKCF_F_LKCF_HW_RSA_PRIV_FUNC, LKCF_R_ENOKEY);	
			break;

		case EKEYEXPIRED:
			LKCFerr(LKCF_F_LKCF_HW_RSA_PRIV_FUNC, LKCF_R_EKEYEXPIRED);	
			break;

		case EACCES:
			LKCFerr(LKCF_F_LKCF_HW_RSA_PRIV_FUNC, LKCF_R_EACCES);	
			break;
			
		case ENOPKG:
			LKCFerr(LKCF_F_LKCF_HW_RSA_PRIV_FUNC, LKCF_R_ENOPKG);	
			break;

		case EFAULT:
			LKCFerr(LKCF_F_LKCF_HW_RSA_PRIV_FUNC, LKCF_R_EFAULT);;
			break;

		default:
			LKCFerr(LKCF_F_LKCF_HW_RSA_PRIV_FUNC, LKCF_R_PKEY_ENCRYPT_ERR);
			break;
		}
	}

	return ret;
}

static int lkcf_rsa_pub_enc(int flen, const unsigned char *from,
		    		        unsigned char *to, RSA *rsa, int padding)
{
	PkeyExCtx *pkey_ctx = lkcf_get_pkey_ctx(rsa);
	int num, i, ret = -1;
	unsigned char* buf = NULL;

	log_debug("TRACE %s", __func__);
	if (!pkey_ctx) {
		return RSA_meth_get_pub_enc(ossl_rsa_meth)
			(flen, from, to, rsa, padding);
	}

	num = RSA_size(rsa);
	buf = OPENSSL_malloc(num);
	switch (padding) {
	case RSA_PKCS1_PADDING:
		i = RSA_padding_add_PKCS1_type_2(buf, num, from, flen);
		break;

	case RSA_PKCS1_OAEP_PADDING:
		i = RSA_padding_add_PKCS1_OAEP(buf, num, from, flen, NULL, 0);
		break;

	case RSA_SSLV23_PADDING:
		i = RSA_padding_add_SSLv23(buf, num, from, flen);
		break;

	case RSA_NO_PADDING:
		i = RSA_padding_add_none(buf, num, from, flen);
		break;

	default:
        LKCFerr(LKCF_F_LKCF_RSA_PUB_ENC, LKCF_R_UNKNOWN_PADDING_TYPE);
		goto error;
	}

	if (i <= 0) {
		goto error;
	}
	ret = lkcf_hw_rsa_pub_func(pkey_ctx, buf, num, to, num);

	/* fallthrough to builtin */
	if (ret < 0) {
		ret = RSA_meth_get_pub_enc(ossl_rsa_meth)
			(flen, from, to, rsa, padding);
	}

error:
	OPENSSL_clear_free(buf, num);
	return ret;
}

static int lkcf_rsa_pub_dec(int flen, const unsigned char *from,
				            unsigned char *to, RSA *rsa, int padding)
{
	PkeyExCtx *pkey_ctx = lkcf_get_pkey_ctx(rsa);
	int ret = -1, num = RSA_size(rsa);
	unsigned char *buf = NULL;
	BIGNUM *plaintext = NULL;

	log_debug("TRACE %s", __func__);
	if (!pkey_ctx) {
		return RSA_meth_get_pub_dec(ossl_rsa_meth)
			(flen, from, to, rsa, padding);
	}

	buf = OPENSSL_malloc(num);
	ret = lkcf_hw_rsa_pub_func(pkey_ctx, from, num, buf, num);

	/* fallthrough to builtin */
	if (ret <= 0) {
		ret = RSA_meth_get_pub_dec(ossl_rsa_meth)
			(flen, from, to, rsa, padding);
		goto error;
	}
	if ((padding == RSA_X931_PADDING)) {
		plaintext = BN_new();
		if (BN_bin2bn(buf, ret, plaintext) <= 0) {
			goto error;
		}
		if ((BN_get_word(plaintext) & 0xf) != 12 && 
		    !BN_sub(plaintext, RSA_get0_n(rsa), plaintext)) {
			goto error;
		}
		ret = BN_bn2binpad(plaintext, buf, num);
	}

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_check_PKCS1_type_1(to, num, buf, ret, num);
		break;

	case RSA_X931_PADDING:
		ret = RSA_padding_check_X931(to, num, buf, ret, num);
		break;

	case RSA_NO_PADDING:
		memcpy(to, buf, ret);
		break;

	default:
        LKCFerr(LKCF_F_LKCF_RSA_PUB_DEC, LKCF_R_UNKNOWN_PADDING_TYPE);
        goto error;
	}

	if (ret < 0) {
        LKCFerr(LKCF_F_LKCF_RSA_PUB_DEC, LKCF_R_PADDING_CHECK_FAILED);
		goto error;
	}

error:
	BN_free(plaintext);
	OPENSSL_clear_free(buf, num);
	return ret;
}

static int lkcf_rsa_priv_enc(int flen, const unsigned char *from,
				             unsigned char *to, RSA *rsa, int padding)
{
	PkeyExCtx *pkey_ctx = lkcf_get_pkey_ctx(rsa);
	unsigned char *buf = NULL;
	BIGNUM *f = NULL, *r = NULL, *res;
	BN_CTX *bn_ctx = NULL;
	int ret = -1, num = RSA_size(rsa);

	log_debug("TRACE %s", __func__);
	if (!pkey_ctx) {
		return RSA_meth_get_priv_enc(ossl_rsa_meth)
			(flen, from, to, rsa, padding);
	}

	buf = OPENSSL_malloc(num);
	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_add_PKCS1_type_1(buf, num, from, flen);
		break;

	case RSA_NO_PADDING:
		ret = RSA_padding_add_none(buf, num, from, flen);
		break;

	case RSA_X931_PADDING:
		ret = RSA_padding_add_X931(buf, num, from, flen);
		break;

	/* RSA_SSLV23 is not allowed for signing */
	case RSA_SSLV23_PADDING:
	default:
        LKCFerr(LKCF_F_LKCF_RSA_PRIV_ENC, LKCF_R_UNKNOWN_PADDING_TYPE);
        goto error;
	}

	if (ret <= 0) {
		LKCFerr(LKCF_F_LKCF_RSA_PRIV_ENC, LKCF_R_PADDING_FAILURE);
		goto error;
	}

	ret = lkcf_hw_rsa_priv_func(pkey_ctx, buf, num, to, num);
	/* fallthrough to builtin */
	if (ret <= 0) {
		ret = RSA_meth_get_priv_enc(ossl_rsa_meth)
			(flen, from, to, rsa, padding);
		goto error;
	}

	if (padding == RSA_X931_PADDING) {
		if ((bn_ctx = BN_CTX_new()) == NULL) {
			goto error;
		}
		BN_CTX_start(bn_ctx);
		f = BN_CTX_get(bn_ctx);
		r = BN_CTX_get(bn_ctx);
		if (BN_bin2bn(buf, ret, f) <= 0) {
			goto error;
		}
		if (BN_bin2bn(to, ret, r) <= 0) {
			goto error;
		}
		if (!BN_sub(f, RSA_get0_n(rsa), r)) {
			goto error;
		}
		if (BN_cmp(r, f) > 0) {
			res = f;
		} else {
			res = r;
		}
		ret = BN_bn2binpad(res, to, num);
	}

error:
	if (bn_ctx != NULL) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	OPENSSL_clear_free(buf, num);
	return ret;
}

static int lkcf_rsa_priv_dec(int flen, const unsigned char *from,
				             unsigned char *to, RSA *rsa, int padding)
{
	PkeyExCtx *pkey_ctx = lkcf_get_pkey_ctx(rsa);
	unsigned char *buf = NULL;
	int ret = -1, num = RSA_size(rsa);

	log_debug("TRACE %s", __func__);
	if (!pkey_ctx) {
		return RSA_meth_get_priv_dec(ossl_rsa_meth)
			(flen, from, to, rsa, padding);
	}

	buf = OPENSSL_malloc(num);
	ret = lkcf_hw_rsa_priv_func(pkey_ctx, from, num, buf, num); 

	/* fallthrough to builtin */
	if (ret <= 0) {
		ret = RSA_meth_get_priv_dec(ossl_rsa_meth)
			(flen, from, to, rsa, padding);
		goto error;
	}

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_check_PKCS1_type_2(to, num, buf, ret, num);
		break;

	case  RSA_PKCS1_OAEP_PADDING:
		ret = RSA_padding_check_PKCS1_OAEP(to, num, buf, ret, num, NULL, 0);
		break;

	case RSA_SSLV23_PADDING:
		ret = RSA_padding_check_SSLv23(to, num, buf, ret, num);
		break;

	case RSA_NO_PADDING:
		memcpy(to, buf, ret);
		break;

	default:
        LKCFerr(LKCF_F_LKCF_RSA_PRIV_DEC, LKCF_R_UNKNOWN_PADDING_TYPE);
        goto error;
	}
	if (ret < 0) {
        LKCFerr(LKCF_F_LKCF_RSA_PRIV_DEC, LKCF_R_PADDING_CHECK_FAILED);
	}

error:
    OPENSSL_clear_free(buf, num);
	return ret;
}
