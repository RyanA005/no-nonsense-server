#ifndef SPOOKY_SHELL_H
#define SPOOKY_SHELL_H

#include "filesystem.h"

#include <stddef.h>
#include <stdint.h>

struct spooky_session {
    char username[33];
    uint32_t uid;
    char cwd[SPOOKY_PATH_MAX];
    char home[SPOOKY_PATH_MAX];
};

struct spooky_output {
    uint8_t status;
    int close_session;
    uint8_t *data;
    size_t len;
};

int shell_exec(struct spooky_session *session, const uint8_t *cmd, size_t cmd_len,
               struct spooky_output *out);

#endif
