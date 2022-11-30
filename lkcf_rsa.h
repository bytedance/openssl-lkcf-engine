#ifndef LKCF_ENGINE_LKCF_RSA_H
#define LKCF_ENGINE_LKCF_RSA_H

#include <openssl/rsa.h>

RSA_METHOD* lkcf_get_RSA_methods(void);
void lkcf_free_RSA_methods(void);

#endif  // LKCF_ENGINE_LKCF_RSA_H
