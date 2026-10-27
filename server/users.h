#ifndef SPOOKY_USERS_H
#define SPOOKY_USERS_H

#include "filesystem.h"

#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>

struct spooky_user {
    char name[33];
    uint32_t uid;
    char home[SPOOKY_PATH_MAX];
    EVP_PKEY *pubkey;
};

int users_load(const char *data_dir, char *err, size_t errlen);
size_t users_count(void);
const struct spooky_user *users_at(size_t index);
const struct spooky_user *users_find(const char *name, size_t len);

#endif
