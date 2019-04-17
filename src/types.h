#ifndef __H_TYPES
#define __H_TYPES

#include <sys/types.h>

/**
 * Files containing all messages
 */

typedef u_int8_t type_t;
typedef u_int64_t chat_id_t;
typedef u_int32_t nonce_t;

typedef struct neighbour {
    chat_id_t id;
    time_t last_hello;
    time_t last_long_hello;
    time_t last_hello_send;
    int pmtu;
    struct sockaddr_in6 *addr;
} neighbour_t;

typedef struct body {
    char *content;
    int size;
    struct body *next;
} body_t;


typedef struct message {
    type_t magic;
    type_t version;
    u_int16_t body_length;
    body_t *body;
    neighbour_t *dst;
} message_t;

int push_tlv(body_t *tlv, neighbour_t *dst);

message_t *pull_message();

#endif
