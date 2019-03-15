/**
 * Files containing all messages
 */

/**
 * All datagrams are encoded with TLV
 * Header for all message
 */

#include <sys/types.h>

#define PAD1 1
#define PADN 0
#define HELLO 2
#define NEIGHBOUR 3
#define DATA 4
#define ACK 5
#define GO_AWAY 6
#define WARNING 7

struct tlv_hdr {
    u_int8_t type;
    u_int8_t length;
};

typedef u_int64_t chat_id_t;

struct hello_msg {
    chat_id_t source_id;
    chat_id_t dest_id;
};

struct neighbour_msg {
    unsigned char ip[16];
    u_int16_t port;
};

/**
 * Ack message is data message without type and data fields
 */
struct data_msg {
    u_int64_t sender_id;
    u_int32_t nonce;
    u_int8_t type;
    char data[];
};

#define UNKNOWN 0
#define LEAVED 1
#define LOST 2
#define VIOLATED 3

struct go_away_msg {
    u_int8_t code;
    char message[];
};

typedef struct message {
    struct tlv_hdr hdr;
    union {
        struct hello_msg hello;
        struct neighbour_msg neighbour;
        struct data_msg data;
        struct go_away_msg go_away;
        char *warning;
    };
} message_t;

/**
 * List of known neighbours
 */
typedef struct neighbour_node {
    id_t id;
    time_t last_hello;
    time_t last_long_hello;
    struct neighbour_node *next;
} neighbour_t;
