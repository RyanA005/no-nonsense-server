#include "auth.h"

#include "crypto.h"

#include <string.h>

int auth_verify(const struct spooky_user *user, const uint8_t challenge[SPOOKY_CHALLENGE_LEN],
                const uint8_t signature[SPOOKY_SIG_LEN]) {
    uint8_t message[128];
    size_t message_len = 0;

    if (user == NULL || user->pubkey == NULL || challenge == NULL || signature == NULL) {
        return -1;
    }
    if (spooky_auth_message((const uint8_t *)user->name, strlen(user->name), challenge,
                            message, sizeof message, &message_len) < 0) {
        return -1;
    }
    return spooky_ecdsa_verify(user->pubkey, message, message_len, signature);
}
