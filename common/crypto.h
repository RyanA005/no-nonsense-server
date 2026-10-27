#ifndef SPOOKY_CRYPTO_H
#define SPOOKY_CRYPTO_H

#include "protocol.h"

#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>

EVP_PKEY *spooky_load_private_key(const char *path);
EVP_PKEY *spooky_load_public_key(const char *path);

int spooky_auth_message(const uint8_t *username, size_t username_len,
                        const uint8_t challenge[SPOOKY_CHALLENGE_LEN],
                        uint8_t *out, size_t out_cap, size_t *out_len);

int spooky_ecdsa_sign(EVP_PKEY *pkey, const uint8_t *msg, size_t msg_len,
                      uint8_t out[SPOOKY_SIG_LEN]);

/* 1 valid, 0 invalid, -1 error. */
int spooky_ecdsa_verify(EVP_PKEY *pkey, const uint8_t *msg, size_t msg_len,
                        const uint8_t sig[SPOOKY_SIG_LEN]);

int spooky_random_bytes(uint8_t *buf, size_t len);

#endif
