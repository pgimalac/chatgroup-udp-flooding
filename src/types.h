#ifndef __H_TYPES
#define __H_TYPES

#include <sys/types.h>

/**
 * Files containing all messages
 */

typedef u_int8_t type_t;
typedef u_int64_t chat_id_t;
typedef u_int32_t nonce_t;

#define BODY_TYPE(body) body->content[0]
#define BODY_SIZE(body) body->content[1]

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
} message_t;

/**
 * List of known neighbours
 */
typedef struct neighbour_node {
    id_t id;
    time_t last_hello;
    time_t last_long_hello;
    struct sockaddr *addr;
    size_t addrlen;
    struct neighbour_node *next;
} neighbour_t;

#endif
