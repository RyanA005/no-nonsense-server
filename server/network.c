#include "network.h"

#include "auth.h"
#include "crypto.h"
#include "protocol.h"
#include "shell.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SPOOKY_MAX_CONN 32
#define SPOOKY_IDLE_SEC 180

enum {
    CONN_FREE = 0,
    CONN_INIT,
    CONN_READY,
    CONN_WAIT_PROOF,
    CONN_AUTHED
};

struct conn {
    int fd;
    int state;
    char username[33];
    uint32_t uid;
    char cwd[SPOOKY_PATH_MAX];
    char home[SPOOKY_PATH_MAX];
    uint8_t challenge[SPOOKY_CHALLENGE_LEN];
    int has_challenge;
    uint8_t inbuf[4 + SPOOKY_MAX_PAYLOAD];
    size_t inlen;
    time_t last_active;
};

static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void close_conn(struct conn *c) {
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    c->state = CONN_FREE;
    c->inlen = 0;
    c->has_challenge = 0;
    memset(c->challenge, 0, sizeof c->challenge);
}

static int send_error(struct conn *c, uint8_t code, const char *msg) {
    uint8_t buf[256];
    size_t n = strlen(msg);

    if (n > sizeof buf - 1) {
        n = sizeof buf - 1;
    }
    buf[0] = code;
    memcpy(buf + 1, msg, n);
    return spooky_write_msg(c->fd, SPOOKY_OP_ERROR, buf, (uint16_t)(n + 1));
}

static int send_exec(struct conn *c, uint8_t status, const uint8_t *data, size_t len) {
    size_t off = 0;

    if (data == NULL) {
        len = 0;
    }
    if (len > SPOOKY_MAX_OUTPUT) {
        len = SPOOKY_MAX_OUTPUT;
    }
    if (len == 0) {
        return spooky_write_msg(c->fd, SPOOKY_OP_EXEC_RESULT, &status, 1);
    }
    while (off < len) {
        uint8_t buf[SPOOKY_MAX_PAYLOAD];
        size_t chunk = len - off;
        int last = 1;

        if (chunk > SPOOKY_MAX_PAYLOAD - 1) {
            chunk = SPOOKY_MAX_PAYLOAD - 1;
            last = 0;
        }
        buf[0] = last ? status : (uint8_t)SPOOKY_EXEC_CONT;
        memcpy(buf + 1, data + off, chunk);
        if (spooky_write_msg(c->fd, SPOOKY_OP_EXEC_RESULT, buf, (uint16_t)(chunk + 1)) < 0) {
            return -1;
        }
        off += chunk;
    }
    return 0;
}

static int username_ok(const uint8_t *name, size_t len) {
    size_t i;

    if (len == 0 || len > 32) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        uint8_t c = name[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

static int handle_auth_start(struct conn *c, const uint8_t *payload, uint16_t len) {
    uint8_t ulen;
    const struct spooky_user *user;

    if (len < 1) {
        send_error(c, SPOOKY_ERR_MALFORMED, "malformed authentication request");
        return -1;
    }
    ulen = payload[0];
    if (ulen == 0 || (size_t)ulen + 1 != (size_t)len || !username_ok(payload + 1, ulen)) {
        send_error(c, SPOOKY_ERR_MALFORMED, "malformed authentication request");
        return -1;
    }
    user = users_find((const char *)(payload + 1), ulen);
    if (user == NULL) {
        send_error(c, SPOOKY_ERR_INVALID, "unknown user");
        return -1;
    }
    if (spooky_random_bytes(c->challenge, sizeof c->challenge) < 0) {
        send_error(c, SPOOKY_ERR_INTERNAL, "internal failure");
        return -1;
    }
    c->has_challenge = 1;
    memcpy(c->username, user->name, strlen(user->name) + 1);
    c->uid = user->uid;
    memcpy(c->home, user->home, strlen(user->home) + 1);
    memcpy(c->cwd, user->home, strlen(user->home) + 1);
    if (spooky_write_msg(c->fd, SPOOKY_OP_AUTH_CHALLENGE, c->challenge, SPOOKY_CHALLENGE_LEN) < 0) {
        return -1;
    }
    c->state = CONN_WAIT_PROOF;
    return 0;
}

static int handle_auth_prove(struct conn *c, const uint8_t *payload, uint16_t len) {
    uint8_t challenge[SPOOKY_CHALLENGE_LEN];
    const struct spooky_user *user;
    uint8_t result;
    int vr;

    if (!c->has_challenge) {
        send_error(c, SPOOKY_ERR_INVALID, "no authentication challenge pending");
        return -1;
    }
    memcpy(challenge, c->challenge, sizeof challenge);
    c->has_challenge = 0;
    memset(c->challenge, 0, sizeof c->challenge);

    if (len != SPOOKY_SIG_LEN) {
        send_error(c, SPOOKY_ERR_MALFORMED, "malformed authentication proof");
        return -1;
    }
    user = users_find(c->username, strlen(c->username));
    if (user == NULL) {
        send_error(c, SPOOKY_ERR_INTERNAL, "internal failure");
        return -1;
    }
    vr = auth_verify(user, challenge, payload);
    memset(challenge, 0, sizeof challenge);
    if (vr < 0) {
        send_error(c, SPOOKY_ERR_INTERNAL, "internal failure");
        return -1;
    }
    if (vr != 1) {
        result = SPOOKY_AUTH_FAIL;
        spooky_write_msg(c->fd, SPOOKY_OP_AUTH_RESULT, &result, 1);
        fprintf(stderr, "auth fail user=%s\n", user->name);
        return -1;
    }
    result = SPOOKY_AUTH_OK;
    if (spooky_write_msg(c->fd, SPOOKY_OP_AUTH_RESULT, &result, 1) < 0) {
        return -1;
    }
    c->state = CONN_AUTHED;
    fprintf(stderr, "auth ok user=%s\n", user->name);
    return 0;
}

static int handle_exec(struct conn *c, const uint8_t *payload, uint16_t len) {
    struct spooky_session session;
    struct spooky_output output;
    int rc;

    memset(&output, 0, sizeof output);
    if (len > SPOOKY_MAX_COMMAND) {
        return send_exec(c, SPOOKY_EXEC_ERR, (const uint8_t *)"command too long\n", 17);
    }

    memset(&session, 0, sizeof session);
    memcpy(session.username, c->username, sizeof session.username);
    session.uid = c->uid;
    memcpy(session.cwd, c->cwd, sizeof session.cwd);
    memcpy(session.home, c->home, sizeof session.home);

    if (shell_exec(&session, payload, len, &output) < 0) {
        free(output.data);
        send_error(c, SPOOKY_ERR_INTERNAL, "internal failure");
        return -1;
    }
    memcpy(c->cwd, session.cwd, sizeof c->cwd);
    rc = send_exec(c, output.status, output.data, output.len);
    if (output.close_session) {
        rc = -1;
    }
    free(output.data);
    return rc;
}

static int handle_message(struct conn *c, uint8_t opcode, const uint8_t *payload, uint16_t len) {
    if (opcode == SPOOKY_OP_LOGOUT) {
        return -1;
    }
    if (opcode == SPOOKY_OP_EXEC && c->state != CONN_AUTHED) {
        if (c->state == CONN_WAIT_PROOF) {
            send_error(c, SPOOKY_ERR_INVALID, "invalid operation");
        } else {
            send_error(c, SPOOKY_ERR_UNAUTH, "unauthenticated");
        }
        return -1;
    }

    if (c->state == CONN_INIT) {
        if (opcode != SPOOKY_OP_HELLO || len != 0) {
            send_error(c, opcode == SPOOKY_OP_HELLO ? SPOOKY_ERR_MALFORMED : SPOOKY_ERR_INVALID,
                       opcode == SPOOKY_OP_HELLO ? "malformed hello" : "invalid operation");
            return -1;
        }
        if (spooky_write_msg(c->fd, SPOOKY_OP_HELLO, (const uint8_t *)SPOOKY_BANNER,
                             (uint16_t)(sizeof SPOOKY_BANNER - 1)) < 0) {
            return -1;
        }
        c->state = CONN_READY;
        return 0;
    }

    if (c->state == CONN_READY) {
        if (opcode != SPOOKY_OP_AUTH_START) {
            send_error(c, SPOOKY_ERR_INVALID, "invalid operation");
            return -1;
        }
        return handle_auth_start(c, payload, len);
    }

    if (c->state == CONN_WAIT_PROOF) {
        if (opcode != SPOOKY_OP_AUTH_PROVE) {
            send_error(c, SPOOKY_ERR_INVALID, "invalid operation");
            return -1;
        }
        return handle_auth_prove(c, payload, len);
    }

    if (c->state == CONN_AUTHED) {
        if (opcode != SPOOKY_OP_EXEC) {
            send_error(c, SPOOKY_ERR_INVALID, "invalid operation");
            return -1;
        }
        return handle_exec(c, payload, len);
    }

    send_error(c, SPOOKY_ERR_INVALID, "invalid operation");
    return -1;
}

static int process_buffer(struct conn *c) {
    uint8_t version;
    uint8_t opcode;
    uint16_t plen;
    uint8_t local[SPOOKY_MAX_PAYLOAD];
    size_t msg;

    if (c->inlen < 4) {
        return 0;
    }
    version = c->inbuf[0];
    opcode = c->inbuf[1];
    plen = (uint16_t)(((uint16_t)c->inbuf[2] << 8) | c->inbuf[3]);
    if (plen > SPOOKY_MAX_PAYLOAD) {
        send_error(c, SPOOKY_ERR_MALFORMED, "payload too large");
        close_conn(c);
        return -1;
    }
    if (c->inlen < 4u + (size_t)plen) {
        return 0;
    }
    memcpy(local, c->inbuf + 4, plen);
    msg = 4u + (size_t)plen;
    memmove(c->inbuf, c->inbuf + msg, c->inlen - msg);
    c->inlen -= msg;

    if (version != SPOOKY_VERSION) {
        send_error(c, SPOOKY_ERR_MALFORMED, "unsupported protocol version");
        close_conn(c);
        return -1;
    }
    if (handle_message(c, opcode, local, plen) < 0) {
        close_conn(c);
        return -1;
    }
    return 1;
}

static void on_readable(struct conn *c) {
    ssize_t n;

    if (c->fd < 0) {
        return;
    }
    if (c->inlen >= sizeof c->inbuf) {
        send_error(c, SPOOKY_ERR_MALFORMED, "malformed packet");
        close_conn(c);
        return;
    }
    n = recv(c->fd, c->inbuf + c->inlen, sizeof c->inbuf - c->inlen, 0);
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        close_conn(c);
        return;
    }
    if (n == 0) {
        close_conn(c);
        return;
    }
    c->inlen += (size_t)n;
    c->last_active = time(NULL);
    while (c->fd >= 0) {
        int rc = process_buffer(c);
        if (rc <= 0) {
            break;
        }
    }
}

static void init_conn(struct conn *c, int fd) {
    memset(c, 0, sizeof *c);
    c->fd = fd;
    c->state = CONN_INIT;
    c->last_active = time(NULL);
}

static int listen_socket(const char *host, int port, int *actual_port) {
    char portstr[16];
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it;
    int fd = -1;
    int rc;
    int opt = 1;

    snprintf(portstr, sizeof portstr, "%d", port);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }

    for (it = res; it != NULL; it = it->ai_next) {
        struct sockaddr_in bound;
        socklen_t bound_len = sizeof bound;

        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
        if (bind(fd, it->ai_addr, it->ai_addrlen) < 0) {
            close(fd);
            fd = -1;
            continue;
        }
        if (listen(fd, 16) < 0) {
            close(fd);
            fd = -1;
            continue;
        }
        if (getsockname(fd, (struct sockaddr *)&bound, &bound_len) < 0) {
            close(fd);
            fd = -1;
            continue;
        }
        *actual_port = ntohs(bound.sin_port);
        if (set_nonblock(fd) < 0) {
            close(fd);
            fd = -1;
            continue;
        }
        break;
    }
    freeaddrinfo(res);
    return fd;
}

static int count_conns(struct conn *conns) {
    int i;
    int n = 0;
    for (i = 0; i < SPOOKY_MAX_CONN; i++) {
        if (conns[i].fd >= 0) {
            n++;
        }
    }
    return n;
}

static void accept_conn(int lfd, struct conn *conns) {
    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        int slot = -1;
        int i;

        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (count_conns(conns) >= SPOOKY_MAX_CONN) {
            close(fd);
            fprintf(stderr, "reject connection: limit reached\n");
            continue;
        }
        for (i = 0; i < SPOOKY_MAX_CONN; i++) {
            if (conns[i].fd < 0) {
                slot = i;
                break;
            }
        }
        if (slot < 0 || set_nonblock(fd) < 0) {
            close(fd);
            continue;
        }
        init_conn(&conns[slot], fd);
        fprintf(stderr, "connection opened\n");
    }
}

int spooky_server_run(const char *host, int port) {
    struct conn conns[SPOOKY_MAX_CONN];
    int lfd;
    int actual = 0;
    int i;

    signal(SIGPIPE, SIG_IGN);
    for (i = 0; i < SPOOKY_MAX_CONN; i++) {
        conns[i].fd = -1;
        conns[i].state = CONN_FREE;
    }
    lfd = listen_socket(host, port, &actual);
    if (lfd < 0) {
        fprintf(stderr, "failed to listen on %s:%d\n", host, port);
        return -1;
    }
    printf("LISTENING %d\n", actual);
    fflush(stdout);
    fprintf(stderr, "spooky-server listening on %s:%d\n", host, actual);

    for (;;) {
        struct pollfd pfds[SPOOKY_MAX_CONN + 1];
        int map[SPOOKY_MAX_CONN + 1];
        int np = 0;
        time_t now = time(NULL);
        int rc;

        pfds[np].fd = lfd;
        pfds[np].events = POLLIN;
        pfds[np].revents = 0;
        map[np] = -1;
        np++;

        for (i = 0; i < SPOOKY_MAX_CONN; i++) {
            if (conns[i].fd < 0) {
                continue;
            }
            if (now - conns[i].last_active > SPOOKY_IDLE_SEC) {
                fprintf(stderr, "connection idle timeout\n");
                close_conn(&conns[i]);
                continue;
            }
            pfds[np].fd = conns[i].fd;
            pfds[np].events = POLLIN;
            pfds[np].revents = 0;
            map[np] = i;
            np++;
        }

        rc = poll(pfds, (nfds_t)np, 1000);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(lfd);
            return -1;
        }
        if (rc == 0) {
            continue;
        }
        if (pfds[0].revents & POLLIN) {
            accept_conn(lfd, conns);
        }
        for (i = 1; i < np; i++) {
            struct conn *c = &conns[map[i]];
            if (c->fd < 0) {
                continue;
            }
            if (pfds[i].revents & POLLIN) {
                on_readable(c);
            } else if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                close_conn(c);
            }
        }
    }
}
