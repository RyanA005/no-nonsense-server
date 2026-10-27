#ifndef SPOOKY_PROTOCOL_H
#define SPOOKY_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define SPOOKY_VERSION 0x01
#define SPOOKY_MAX_PAYLOAD 1024
#define SPOOKY_MAX_COMMAND 256
#define SPOOKY_BANNER "SP00KY/1 - Remote Access Service"

#define SPOOKY_OP_HELLO 0x01
#define SPOOKY_OP_AUTH_START 0x02
#define SPOOKY_OP_AUTH_CHALLENGE 0x03
#define SPOOKY_OP_AUTH_PROVE 0x04
#define SPOOKY_OP_AUTH_RESULT 0x05
#define SPOOKY_OP_EXEC 0x06
#define SPOOKY_OP_EXEC_RESULT 0x07
#define SPOOKY_OP_ERROR 0x08
#define SPOOKY_OP_LOGOUT 0x09

#define SPOOKY_AUTH_FAIL 0x00
#define SPOOKY_AUTH_OK 0x01

#define SPOOKY_EXEC_OK 0x00
#define SPOOKY_EXEC_ERR 0x01
#define SPOOKY_EXEC_DENIED 0x02
#define SPOOKY_EXEC_CONT 0x03

#define SPOOKY_ERR_MALFORMED 0x01
#define SPOOKY_ERR_INVALID 0x02
#define SPOOKY_ERR_UNAUTH 0x03
#define SPOOKY_ERR_INTERNAL 0x04

#define SPOOKY_CHALLENGE_LEN 32
#define SPOOKY_SIG_LEN 64

int spooky_write_msg(int fd, uint8_t opcode, const uint8_t *payload, uint16_t length);
/* returns 0 on success and -1 on failure. */
int spooky_read_msg(int fd, uint8_t *opcode, uint8_t *payload, uint16_t *length);
/* returns -2 when the header length exceeds the maximum. */

#endif
