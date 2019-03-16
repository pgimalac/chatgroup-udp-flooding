#ifndef __H_TYPES
#define __H_TYPES

#include <sys/types.h>

/**
 * Files containing all messages
 */

#define BODY_PAD1 0
#define BODY_PADN 1
#define BODY_HELLO 2
#define BODY_NEIGHBOUR 3
#define BODY_DATA 4
#define BODY_ACK 5
#define BODY_GO_AWAY 6
#define BODY_WARNING 7

#define AWAY_UNKNOWN 0
#define AWAY_LEAVED 1
#define AWAY_LOST 2
#define AWAY_VIOLATED 3

#define BODY_H_SIZE 2

typedef u_int8_t type_t;
typedef u_int64_t chat_id_t;
typedef u_int32_t nonce_t;


typedef struct body {
    type_t type;
    type_t length;
    void *content;
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
