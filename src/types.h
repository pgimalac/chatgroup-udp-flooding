#ifndef __H_TYPES
#define __H_TYPES

#include <sys/types.h>
#include "structs/hashmap.h"

/**
 * Files containing all messages
 */

typedef u_int8_t type_t;
typedef u_int64_t chat_id_t;
typedef u_int32_t nonce_t;

#define NEIGHBOUR_POT 0
#define NEIGHBOUR_SYM 1

typedef struct neighbour {
    chat_id_t id;
    time_t last_hello;
    time_t last_long_hello;
    time_t last_hello_send;
    int pmtu;
    unsigned char status;
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

typedef struct data_info {
    neighbour_t *neighbour;
    size_t send_count;
    time_t time;
} data_info_t;

#endif
