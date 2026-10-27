#include "crypto.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <stdlib.h>
#include <string.h>

static int is_p256(EVP_PKEY *pkey) {
    char group[64];
    size_t glen = 0;

    if (pkey == NULL) {
        return 0;
    }
    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC) {
        return 0;
    }
    if (EVP_PKEY_get_group_name(pkey, group, sizeof group, &glen) != 1) {
        return 0;
    }
    return strcmp(group, "prime256v1") == 0 || strcmp(group, "P-256") == 0;
}

static EVP_PKEY *load_pem(const char *path, int private_key) {
    BIO *bio;
    EVP_PKEY *pkey;

    bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        return NULL;
    }
    if (private_key) {
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    } else {
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }
    BIO_free(bio);
    if (!is_p256(pkey)) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    return pkey;
}

EVP_PKEY *spooky_load_private_key(const char *path) {
    return load_pem(path, 1);
}

EVP_PKEY *spooky_load_public_key(const char *path) {
    return load_pem(path, 0);
}

int spooky_auth_message(const uint8_t *username, size_t username_len,
                        const uint8_t challenge[SPOOKY_CHALLENGE_LEN],
                        uint8_t *out, size_t out_cap, size_t *out_len) {
    static const char prefix[] = "SP00KY-AUTH-v1";
    const size_t prefix_len = sizeof prefix - 1;
    size_t total;

    if (username == NULL || challenge == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    if (username_len == 0 || username_len > 255) {
        return -1;
    }
    total = prefix_len + 1 + username_len + SPOOKY_CHALLENGE_LEN;
    if (total > out_cap) {
        return -1;
    }

    memcpy(out, prefix, prefix_len);
    out[prefix_len] = (uint8_t)username_len;
    memcpy(out + prefix_len + 1, username, username_len);
    memcpy(out + prefix_len + 1 + username_len, challenge, SPOOKY_CHALLENGE_LEN);
    *out_len = total;
    return 0;
}

/* Encode an unsigned big-endian integer as a DER INTEGER body. */
static size_t der_integer(const uint8_t in[32], uint8_t out[33]) {
    size_t start = 0;
    size_t n;
    int pad;

    while (start + 1 < 32 && in[start] == 0) {
        start++;
    }
    n = 32 - start;
    pad = (in[start] & 0x80) != 0;
    if (pad) {
        out[0] = 0x00;
        memcpy(out + 1, in + start, n);
        return n + 1;
    }
    memcpy(out, in + start, n);
    return n;
}

static int integer_to_fixed(const uint8_t *in, size_t len, uint8_t out[32]) {
    if (len == 0 || len > 33) {
        return -1;
    }
    if ((in[0] & 0x80) != 0) {
        return -1;
    }
    if (len == 33) {
        if (in[0] != 0x00) {
            return -1;
        }
        in++;
        len--;
    }
    if (len > 32) {
        return -1;
    }
    memset(out, 0, 32);
    memcpy(out + (32 - len), in, len);
    return 0;
}

static int rs_to_der(const uint8_t sig[SPOOKY_SIG_LEN], uint8_t *der, size_t *der_len) {
    uint8_t r[33];
    uint8_t s[33];
    size_t rl;
    size_t sl;
    size_t body;
    size_t pos;

    rl = der_integer(sig, r);
    sl = der_integer(sig + 32, s);
    body = 2 + rl + 2 + sl;
    if (body > 127) {
        return -1;
    }

    der[0] = 0x30;
    der[1] = (uint8_t)body;
    der[2] = 0x02;
    der[3] = (uint8_t)rl;
    memcpy(der + 4, r, rl);
    pos = 4 + rl;
    der[pos++] = 0x02;
    der[pos++] = (uint8_t)sl;
    memcpy(der + pos, s, sl);
    *der_len = pos + sl;
    return 0;
}

static int der_to_rs(const uint8_t *der, size_t der_len, uint8_t out[SPOOKY_SIG_LEN]) {
    size_t pos = 0;
    size_t body;
    size_t rl;
    size_t sl;

    if (der_len < 8 || der[0] != 0x30) {
        return -1;
    }
    if ((der[1] & 0x80) != 0) {
        return -1;
    }
    body = der[1];
    if (body + 2 != der_len) {
        return -1;
    }
    pos = 2;
    if (der[pos++] != 0x02) {
        return -1;
    }
    rl = der[pos++];
    if (rl == 0 || pos + rl > der_len) {
        return -1;
    }
    if (integer_to_fixed(der + pos, rl, out) < 0) {
        return -1;
    }
    pos += rl;
    if (pos >= der_len || der[pos++] != 0x02) {
        return -1;
    }
    if (pos >= der_len) {
        return -1;
    }
    sl = der[pos++];
    if (sl == 0 || pos + sl != der_len) {
        return -1;
    }
    if (integer_to_fixed(der + pos, sl, out + 32) < 0) {
        return -1;
    }
    return 0;
}

int spooky_ecdsa_sign(EVP_PKEY *pkey, const uint8_t *msg, size_t msg_len,
                      uint8_t out[SPOOKY_SIG_LEN]) {
    EVP_MD_CTX *ctx;
    uint8_t *der = NULL;
    size_t der_len = 0;
    int rc = -1;

    if (pkey == NULL || msg == NULL || out == NULL) {
        return -1;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        goto done;
    }
    if (EVP_DigestSignUpdate(ctx, msg, msg_len) != 1) {
        goto done;
    }
    if (EVP_DigestSignFinal(ctx, NULL, &der_len) != 1 || der_len == 0 || der_len > 128) {
        goto done;
    }
    der = malloc(der_len);
    if (der == NULL) {
        goto done;
    }
    if (EVP_DigestSignFinal(ctx, der, &der_len) != 1) {
        goto done;
    }
    if (der_to_rs(der, der_len, out) < 0) {
        goto done;
    }
    rc = 0;

done:
    if (rc != 0) {
        ERR_clear_error();
    }
    free(der);
    EVP_MD_CTX_free(ctx);
    return rc;
}

int spooky_ecdsa_verify(EVP_PKEY *pkey, const uint8_t *msg, size_t msg_len,
                        const uint8_t sig[SPOOKY_SIG_LEN]) {
    EVP_MD_CTX *ctx;
    uint8_t der[80];
    size_t der_len = 0;
    int vr;
    int rc = -1;

    if (pkey == NULL || msg == NULL || sig == NULL) {
        return -1;
    }
    if (rs_to_der(sig, der, &der_len) < 0) {
        return 0;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        goto done;
    }
    if (EVP_DigestVerifyUpdate(ctx, msg, msg_len) != 1) {
        goto done;
    }
    vr = EVP_DigestVerifyFinal(ctx, der, der_len);
    if (vr == 1) {
        rc = 1;
    } else if (vr == 0) {
        rc = 0;
    } else {
        rc = -1;
    }

done:
    if (rc < 0) {
        ERR_clear_error();
    }
    EVP_MD_CTX_free(ctx);
    return rc;
}

int spooky_random_bytes(uint8_t *buf, size_t len) {
    if (buf == NULL || len == 0 || len > 1024) {
        return -1;
    }
    if (RAND_bytes(buf, (int)len) != 1) {
        ERR_clear_error();
        return -1;
    }
    return 0;
}
