#include "protocol.h"

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int write_full(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;

    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd;
                int rc;

                pfd.fd = fd;
                pfd.events = POLLOUT;
                pfd.revents = 0;
                rc = poll(&pfd, 1, 10000);
                if (rc <= 0) {
                    return -1;
                }
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static int read_full(int fd, uint8_t *buf, size_t len) {
    size_t off = 0;

    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd;
                int rc;

                pfd.fd = fd;
                pfd.events = POLLIN;
                pfd.revents = 0;
                rc = poll(&pfd, 1, 10000);
                if (rc <= 0) {
                    return -1;
                }
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

int spooky_write_msg(int fd, uint8_t opcode, const uint8_t *payload, uint16_t length) {
    uint8_t header[4];

    if (length > SPOOKY_MAX_PAYLOAD) {
        return -1;
    }
    if (length > 0 && payload == NULL) {
        return -1;
    }

    header[0] = SPOOKY_VERSION;
    header[1] = opcode;
    header[2] = (uint8_t)((length >> 8) & 0xff);
    header[3] = (uint8_t)(length & 0xff);

    if (write_full(fd, header, sizeof header) < 0) {
        return -1;
    }
    if (length > 0 && write_full(fd, payload, length) < 0) {
        return -1;
    }
    return 0;
}

int spooky_read_msg(int fd, uint8_t *opcode, uint8_t *payload, uint16_t *length) {
    uint8_t header[4];
    uint16_t plen;

    if (opcode == NULL || payload == NULL || length == NULL) {
        return -1;
    }
    if (read_full(fd, header, sizeof header) < 0) {
        return -1;
    }

    plen = (uint16_t)(((uint16_t)header[2] << 8) | header[3]);
    *length = plen;
    *opcode = header[1];
    if (header[0] != SPOOKY_VERSION) {
        return -2;
    }
    if (plen > SPOOKY_MAX_PAYLOAD) {
        return -2;
    }
    if (plen > 0 && read_full(fd, payload, plen) < 0) {
        return -1;
    }
    return 0;
}
