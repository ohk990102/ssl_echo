#ifndef _SSL_ECHO_HEADER
#define _SSL_ECHO_HEADER
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_BUF_SIZE  (1 << (sizeof(uint16_t) * 8))

#define ECHO_MAGIC "ECHO"

enum ECHO_VERSION {
    v1
};

enum ECHO_CMD {
    SEND,
    END,
};
#pragma pack(push, 1)
struct echo_header_v1 {
    char magic[4];
    uint8_t version;
    uint8_t cmd;
    uint16_t body_len;
};
#pragma pack(pop)

inline size_t construct_echo_msg_v1(void **msg, uint8_t cmd, void *body, uint16_t body_len) {
    size_t len = sizeof(struct echo_header_v1) + body_len;
    void *ret = malloc(len);
    struct echo_header_v1 *echo_header_view = (struct echo_header_v1 *)ret;
    memcpy(echo_header_view->magic, ECHO_MAGIC, sizeof(echo_header_view->magic));
    echo_header_view->version = ECHO_VERSION::v1;
    echo_header_view->cmd = cmd;
    echo_header_view->body_len = htons(body_len);
    memcpy((void *)((uint8_t *) ret + sizeof(struct echo_header_v1)), body, body_len);
    *msg = ret;
    return len;
}

#endif  // _SSL_ECHO_HEADER