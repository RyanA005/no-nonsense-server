#ifndef SPOOKY_AUTH_H
#define SPOOKY_AUTH_H

#include "protocol.h"
#include "users.h"

#include <stdint.h>

/* 1 valid, 0 invalid, -1 internal error. */
int auth_verify(const struct spooky_user *user, const uint8_t challenge[SPOOKY_CHALLENGE_LEN],
                const uint8_t signature[SPOOKY_SIG_LEN]);

#endif
