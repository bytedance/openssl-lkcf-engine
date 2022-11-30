#ifndef LKCF_ENGINE_KEYCTL_H
#define LKCF_ENGINE_KEYCTL_H

#include <keyutils.h>
#include <stdbool.h>
#include <openssl/rsa.h>

#define LKCF_DESC_MAX_LEN 64

#define KEY_TYPE_PKEY "asymmetric"
#define KEY_TYPE_DH_PARAM "user"

/*
 * According to the document of keyctl, -1 always is an illegal
 * key_serial_t value.
 */
#define INVALID_KEYCTL_ID -1

typedef struct PkeyExCtx {
	key_serial_t id;
	char desc[LKCF_DESC_MAX_LEN];
} PkeyExCtx;

int lkcf_init();
int lkcf_destroy();

static inline bool lkcf_pkey_error(PkeyExCtx *pkey_ctx)
{
	return pkey_ctx->id == INVALID_KEYCTL_ID;
}

static inline bool lkcf_pkey_uninitialized(PkeyExCtx *pkey_ctx)
{
	return pkey_ctx->desc[0] == '\0';
}

static inline bool lkcf_pkey_ready(PkeyExCtx *pkey_ctx)
{
	return !lkcf_pkey_uninitialized(pkey_ctx) &&
	       !lkcf_pkey_error(pkey_ctx);
}

static inline PkeyExCtx *lkcf_pkey_ctx_new()
{
	return OPENSSL_zalloc(sizeof(PkeyExCtx));
}

#define lkcf_unlink_key(key_id)								          \
	({													              \
		int _ret;													  \
		log_debug("Going to unlink key: %d", (key_id));				  \
		_ret = keyctl_unlink((key_id), KEY_SPEC_PROCESS_KEYRING);     \
		if (_ret == -1) {											  \
			log_error("Failed to unlink key: %d", (key_id));		  \
		}															  \
		_ret;														  \
	})

#define lkcf_pkey_ctx_free(pkey_ctx)							      \
	do {															  \
		if (!(pkey_ctx) || !lkcf_pkey_ready((pkey_ctx))) {			  \
			break;													  \
		}														      \
		lkcf_unlink_key((pkey_ctx)->id);							  \
	} while (false)													  \

#define lkcf_free_dh_ctx(dh_ctx) \
	do { \
		if ((dh_ctx)->priv > 0) { \
			lkcf_unlink_key((dh_ctx)->priv); \
		} \
		if ((dh_ctx)->p > 0) { \
			lkcf_unlink_key((dh_ctx)->p); \
		} \
		if ((dh_ctx)->g > 0) { \
			lkcf_unlink_key((dh_ctx)->g); \
		} \
	} while (false)

int lkcf_pkey_add(PkeyExCtx *pkey_ctx,
                  const unsigned char *payload,
                  size_t payload_len);

int lkcf_upload_rsa_privkey(PkeyExCtx *pkey_ctx, RSA *rsa);

#endif  // LKCF_ENGINE_KEYCTL_H
