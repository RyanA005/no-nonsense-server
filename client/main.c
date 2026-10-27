/*
 * this is the C source for a basic implementor of the client side SP00KY protocol.
 * there is no need to modify this code in order to solve the challenge.
 * code is authored by ryan alport, direct any questions to ctf@ryanhub.org
 */

#include "crypto.h"
#include "protocol.h"

#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <getopt.h>

static void usage(FILE *fp) {
    fputs("usage: spooky-client --host HOST --port PORT --user USER --key KEY\n", fp);
}

static int connect_host(const char *host, const char *port) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it;
    int fd = -1;
    int rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }
    for (it = res; it != NULL; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        fprintf(stderr, "connection failed\n");
    }
    return fd;
}

static int read_exec(int fd, uint8_t *status_out) {
    for (;;) {
        uint8_t opcode = 0;
        uint8_t payload[SPOOKY_MAX_PAYLOAD];
        uint16_t len = 0;
        int rc = spooky_read_msg(fd, &opcode, payload, &len);

        if (rc == -2) {
            fprintf(stderr, "rejected packet from server\n");
            return -1;
        }
        if (rc < 0) {
            fprintf(stderr, "connection closed\n");
            return -1;
        }
        if (opcode == SPOOKY_OP_ERROR) {
            if (len > 0) {
                fwrite(payload + 1, 1, len - 1, stderr);
                fputc('\n', stderr);
            } else {
                fprintf(stderr, "server error\n");
            }
            return -1;
        }
        if (opcode != SPOOKY_OP_EXEC_RESULT || len < 1) {
            fprintf(stderr, "unexpected server message\n");
            return -1;
        }
        if (len > 1) {
            fwrite(payload + 1, 1, (size_t)len - 1, stdout);
        }
        *status_out = payload[0];
        if (payload[0] != SPOOKY_EXEC_CONT) {
            return 0;
        }
    }
}

static int query_pwd(int fd, char *cwd, size_t cwd_sz) {
    static const char cmd[] = "pwd";
    uint8_t opcode = 0;
    uint8_t payload[SPOOKY_MAX_PAYLOAD];
    uint16_t len = 0;
    size_t n;
    int rc;

    if (spooky_write_msg(fd, SPOOKY_OP_EXEC, (const uint8_t *)cmd, (uint16_t)(sizeof cmd - 1)) < 0) {
        return -1;
    }
    rc = spooky_read_msg(fd, &opcode, payload, &len);
    if (rc < 0 || opcode != SPOOKY_OP_EXEC_RESULT || len < 2 || payload[0] != SPOOKY_EXEC_OK) {
        return -1;
    }
    n = (size_t)len - 1;
    while (n > 0 && (payload[n] == '\n' || payload[n] == '\r')) {
        n--;
    }
    if (n == 0 || n + 1 > cwd_sz) {
        return -1;
    }
    memcpy(cwd, payload + 1, n);
    cwd[n] = '\0';
    return 0;
}

static void make_prompt(char *out, size_t out_sz, const char *user, const char *cwd, const char *home) {
    const char *shown = cwd;
    char tmp[512];
    size_t home_len = strlen(home);

    if (strcmp(cwd, home) == 0) {
        shown = "~";
    } else if (strncmp(cwd, home, home_len) == 0 && cwd[home_len] == '/') {
        snprintf(tmp, sizeof tmp, "~%s", cwd + home_len);
        shown = tmp;
    }
    snprintf(out, out_sz, "%s@spooky:%s$ ", user, shown);
}

static int starts_with_cd(const char *line) {
    if (strncmp(line, "cd", 2) != 0) {
        return 0;
    }
    return line[2] == '\0' || line[2] == ' ' || line[2] == '\t';
}

static int authenticate(int fd, EVP_PKEY *key, const char *user) {
    uint8_t body[64];
    uint8_t opcode = 0;
    uint8_t payload[SPOOKY_MAX_PAYLOAD];
    uint16_t len = 0;
    uint8_t message[128];
    size_t message_len = 0;
    uint8_t signature[SPOOKY_SIG_LEN];
    size_t user_len = strlen(user);

    if (user_len == 0 || user_len > 32) {
        fprintf(stderr, "invalid username\n");
        return -1;
    }
    if (spooky_write_msg(fd, SPOOKY_OP_HELLO, NULL, 0) < 0) {
        return -1;
    }
    if (spooky_read_msg(fd, &opcode, payload, &len) < 0 || opcode != SPOOKY_OP_HELLO) {
        fprintf(stderr, "hello failed\n");
        return -1;
    }
    fwrite(payload, 1, len, stdout);
    fputc('\n', stdout);

    body[0] = (uint8_t)user_len;
    memcpy(body + 1, user, user_len);
    if (spooky_write_msg(fd, SPOOKY_OP_AUTH_START, body, (uint16_t)(user_len + 1)) < 0) {
        return -1;
    }
    if (spooky_read_msg(fd, &opcode, payload, &len) < 0 || opcode != SPOOKY_OP_AUTH_CHALLENGE ||
        len != SPOOKY_CHALLENGE_LEN) {
        fprintf(stderr, "authentication challenge failed\n");
        return -1;
    }
    if (spooky_auth_message((const uint8_t *)user, user_len, payload, message, sizeof message,
                            &message_len) < 0) {
        return -1;
    }
    if (spooky_ecdsa_sign(key, message, message_len, signature) < 0) {
        fprintf(stderr, "failed to sign challenge\n");
        return -1;
    }
    if (spooky_write_msg(fd, SPOOKY_OP_AUTH_PROVE, signature, SPOOKY_SIG_LEN) < 0) {
        return -1;
    }
    if (spooky_read_msg(fd, &opcode, payload, &len) < 0 || opcode != SPOOKY_OP_AUTH_RESULT ||
        len != 1 || payload[0] != SPOOKY_AUTH_OK) {
        fprintf(stderr, "authentication failed\n");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    const char *port = "19160";
    const char *user = NULL;
    const char *key_path = NULL;
    EVP_PKEY *key = NULL;
    char cwd[512];
    char home[512];
    int fd = -1;
    int opt;

    static struct option opts[] = {
        {"host", required_argument, NULL, 1},
        {"port", required_argument, NULL, 2},
        {"user", required_argument, NULL, 3},
        {"key", required_argument, NULL, 4},
        {"help", no_argument, NULL, 5},
        {NULL, 0, NULL, 0},
    };

    while ((opt = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch (opt) {
        case 1:
            host = optarg;
            break;
        case 2:
            port = optarg;
            break;
        case 3:
            user = optarg;
            break;
        case 4:
            key_path = optarg;
            break;
        case 5:
            usage(stdout);
            return 0;
        default:
            usage(stderr);
            return 1;
        }
    }
    if (user == NULL || key_path == NULL) {
        usage(stderr);
        return 1;
    }

    key = spooky_load_private_key(key_path);
    if (key == NULL) {
        fprintf(stderr, "cannot load private key %s\n", key_path);
        return 1;
    }
    fd = connect_host(host, port);
    if (fd < 0) {
        EVP_PKEY_free(key);
        return 1;
    }
    if (authenticate(fd, key, user) < 0) {
        EVP_PKEY_free(key);
        close(fd);
        return 1;
    }
    EVP_PKEY_free(key);

    snprintf(home, sizeof home, "/home/%s", user);
    memcpy(cwd, home, strlen(home) + 1);
    if (query_pwd(fd, cwd, sizeof cwd) == 0) {
        if (strcmp(cwd, home) != 0) {
            memcpy(home, cwd, strlen(cwd) + 1);
        }
    }

    for (;;) {
        char prompt[640];
        char line[512];
        size_t n;
        uint8_t status = 0;

        make_prompt(prompt, sizeof prompt, user, cwd, home);
        fputs(prompt, stdout);
        fflush(stdout);
        if (fgets(line, sizeof line, stdin) == NULL) {
            spooky_write_msg(fd, SPOOKY_OP_LOGOUT, NULL, 0);
            break;
        }
        n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
            line[--n] = '\0';
        }
        if (n == 0) {
            continue;
        }
        if (n > SPOOKY_MAX_COMMAND) {
            fprintf(stderr, "command too long\n");
            continue;
        }
        if (strcmp(line, "exit") == 0) {
            spooky_write_msg(fd, SPOOKY_OP_LOGOUT, NULL, 0);
            break;
        }
        if (spooky_write_msg(fd, SPOOKY_OP_EXEC, (const uint8_t *)line, (uint16_t)n) < 0) {
            fprintf(stderr, "connection closed\n");
            close(fd);
            return 1;
        }
        if (read_exec(fd, &status) < 0) {
            close(fd);
            return 1;
        }
        fflush(stdout);
        if (status == SPOOKY_EXEC_OK && starts_with_cd(line)) {
            if (query_pwd(fd, cwd, sizeof cwd) < 0) {
                fprintf(stderr, "failed to update working directory\n");
            }
        }
    }

    close(fd);
    return 0;
}
