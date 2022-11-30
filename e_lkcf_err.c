/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include "e_lkcf_err.h"

#ifndef OPENSSL_NO_ERR

static ERR_STRING_DATA LKCF_str_functs[] = {
    {ERR_PACK(0, LKCF_F_LKCF_HW_RSA_PRIV_FUNC, 0), "lkcf_hw_rsa_priv_func"},
    {ERR_PACK(0, LKCF_F_LKCF_HW_RSA_PUB_FUNC, 0), "lkcf_hw_rsa_pub_func"},
    {ERR_PACK(0, LKCF_F_LKCF_INIT, 0), "lkcf_init"},
    {ERR_PACK(0, LKCF_F_LKCF_PKEY_ADD, 0), "lkcf_pkey_add"},
    {ERR_PACK(0, LKCF_F_LKCF_RSA_PRIV_DEC, 0), "lkcf_rsa_priv_dec"},
    {ERR_PACK(0, LKCF_F_LKCF_RSA_PRIV_ENC, 0), "lkcf_rsa_priv_enc"},
    {ERR_PACK(0, LKCF_F_LKCF_RSA_PUB_DEC, 0), "lkcf_rsa_pub_dec"},
    {ERR_PACK(0, LKCF_F_LKCF_RSA_PUB_ENC, 0), "lkcf_rsa_pub_enc"},
    {ERR_PACK(0, LKCF_F_LKCF_UPLOAD_RSA_PRIVKEY, 0), "lkcf_upload_rsa_privkey"},
    {0, NULL}
};

static ERR_STRING_DATA LKCF_str_reasons[] = {
    {ERR_PACK(0, 0, LKCF_R_EACCES), "eacces"},
    {ERR_PACK(0, 0, LKCF_R_EFAULT), "efault"},
    {ERR_PACK(0, 0, LKCF_R_EKEYEXPIRED), "ekeyexpired"},
    {ERR_PACK(0, 0, LKCF_R_ENOKEY), "enokey"},
    {ERR_PACK(0, 0, LKCF_R_ENOPKG), "enopkg"},
    {ERR_PACK(0, 0, LKCF_R_INVALID_RSA_KEY), "invalid rsa key"},
    {ERR_PACK(0, 0, LKCF_R_KEYCTL_ADD_FAILURE), "keyctl add failure"},
    {ERR_PACK(0, 0, LKCF_R_LKCF_INVALID_PAYLOAD), "lkcf invalid payload"},
    {ERR_PACK(0, 0, LKCF_R_PADDING_CHECK_FAILED), "padding check failed"},
    {ERR_PACK(0, 0, LKCF_R_PADDING_FAILURE), "padding failure"},
    {ERR_PACK(0, 0, LKCF_R_PKEY_ENCRYPT_ERR), "pkey encrypt err"},
    {ERR_PACK(0, 0, LKCF_R_UNKNOWN_PADDING_TYPE), "unknown padding type"},
    {0, NULL}
};

#endif

static int lib_code = 0;
static int error_loaded = 0;

int ERR_load_LKCF_strings(void)
{
    if (lib_code == 0)
        lib_code = ERR_get_next_error_library();

    if (!error_loaded) {
#ifndef OPENSSL_NO_ERR
        ERR_load_strings(lib_code, LKCF_str_functs);
        ERR_load_strings(lib_code, LKCF_str_reasons);
#endif
        error_loaded = 1;
    }
    return 1;
}

void ERR_unload_LKCF_strings(void)
{
    if (error_loaded) {
#ifndef OPENSSL_NO_ERR
        ERR_unload_strings(lib_code, LKCF_str_functs);
        ERR_unload_strings(lib_code, LKCF_str_reasons);
#endif
        error_loaded = 0;
    }
}

void ERR_LKCF_error(int function, int reason, char *file, int line)
{
    if (lib_code == 0)
        lib_code = ERR_get_next_error_library();
    ERR_PUT_error(lib_code, function, reason, file, line);
}