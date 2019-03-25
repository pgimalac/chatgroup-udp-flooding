#include "tlv.h"
#include "network.h"

#include <string.h>
#include <endian.h>
#include <stdio.h>

#define HEADER_OFFSET 2

int tlv_pad(char **buffer){
    *buffer = malloc(1);
    if (*buffer == NULL)
        return -1;

    **buffer = BODY_PAD1;

    return 1;
}

int tlv_padn(char **buffer, u_int8_t n){
    int size = HEADER_OFFSET + n;
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    (*buffer)[0] = BODY_PADN;
    (*buffer)[1] = n;
    memset(*buffer + HEADER_OFFSET, 0, n);

    return size;
}

int tlv_hello_short(char **buffer, chat_id_t source){
    chat_id_t n_source = htobe64(source);

    int size = HEADER_OFFSET + sizeof(n_source);
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    (*buffer)[0] = BODY_HELLO;
    (*buffer)[1] = sizeof(source);
    memmove(HEADER_OFFSET + *buffer, &n_source, sizeof(n_source));

    return size;
}

int tlv_hello_long(char **buffer, chat_id_t source, chat_id_t dest){
    u_int64_t n_source = htobe64(source);
    u_int64_t n_dest = htobe64(dest);

    int size = HEADER_OFFSET + sizeof(n_source) + sizeof(n_dest);
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    char *offset = *buffer + HEADER_OFFSET;
    (*buffer)[0] = BODY_HELLO;
    (*buffer)[1] = sizeof(source) + sizeof(dest);
    memmove(offset, &n_source, sizeof(n_source));
    memmove(offset + sizeof(source), &n_dest, sizeof(n_dest));

    return size;
}

int tlv_neighbour(char **buffer, const struct in6_addr *addr, u_int16_t port){
    u_int16_t n_port = htons(port);
    int size = HEADER_OFFSET + sizeof(struct in6_addr) + sizeof(n_port);

    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    char *offset = *buffer + HEADER_OFFSET;
    (*buffer)[0] = BODY_NEIGHBOUR;
    (*buffer)[1] = sizeof(struct in6_addr) + sizeof(n_port);
    memmove(offset, addr, sizeof(struct in6_addr));
    memmove(offset + sizeof(struct in6_addr), &n_port, sizeof(n_port));

    return size;
}

int tlv_data(char **buffer,
             chat_id_t sender, nonce_t nonce,
             u_int8_t type, const char *data, u_int8_t datalen){
    u_int64_t n_sender = htobe64(sender);
    u_int32_t n_nonce = htonl(nonce);
    u_int32_t true_size = datalen + sizeof(n_sender) + sizeof(n_nonce) + sizeof(type);
    if (true_size > 255)
        return -2;

    int size = HEADER_OFFSET + true_size;
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    char *offset = *buffer + HEADER_OFFSET;
    (*buffer)[0] = BODY_DATA;
    (*buffer)[1] = (u_int8_t) true_size;
    memmove(offset, &n_sender, sizeof(n_sender));
    offset += sizeof(n_sender);
    memmove(offset, &n_nonce, sizeof(n_nonce));
    offset += sizeof(n_nonce);
    *offset = type;
    memmove(offset + 1, data, datalen);

    return size;
}

int tlv_ack(char **buffer, u_int64_t sender, u_int32_t nonce){
    u_int64_t n_sender = htobe64(sender);
    u_int64_t n_nonce = htobe64(nonce);

    int size = HEADER_OFFSET + sizeof(n_sender) + sizeof(n_nonce);
    *buffer = malloc(size);

    char *offset = *buffer + HEADER_OFFSET;
    (*buffer)[0] = BODY_ACK;
    (*buffer)[1] = sizeof(n_sender) + sizeof(n_nonce);
    memmove(offset, &n_sender, sizeof(n_sender));
    memmove(offset + sizeof(n_sender), &n_nonce, sizeof(n_nonce));

    return size;
}

int tlv_goaway(char **buffer, u_int8_t code,
               const char *message, u_int8_t messagelen){
    if (messagelen + sizeof(code) > 255)
        return -2;

    int size = HEADER_OFFSET + sizeof(code) + messagelen;
    *buffer = malloc(size);

    (*buffer)[0] = BODY_GO_AWAY;
    (*buffer)[1] = messagelen + sizeof(code);
    (*buffer)[2] = code;
    memmove(*buffer + HEADER_OFFSET, message, messagelen);

    return size;
}

int tlv_warning(char **buffer, const char *message, u_int8_t messagelen){
    int size = HEADER_OFFSET + messagelen;
    *buffer = malloc(size);

    (*buffer)[0] = BODY_WARNING;
    (*buffer)[1] = messagelen;
    memmove(*buffer + HEADER_OFFSET, message, messagelen);

    return size;
}

static void handle_pad1(const body_t *tlv){
    printf("Pad1 received\n");
}

static void handle_padn(const body_t *tlv){
    printf("Pad %d received : \n", BODY_SIZE(tlv));
}

#define TLV_HELLO_ID_SOURCE(tlv) be64toh(*(chat_id_t*)(tlv->content + HEADER_OFFSET))
#define TLV_HELLO_ID_DEST(tlv) be64toh(*(chat_id_t*)(tlv->content + HEADER_OFFSET + sizeof(chat_id_t)))

static void handle_hello(const body_t *tlv){
    chat_id_t source = TLV_HELLO_ID_SOURCE(tlv), dest = htobe64(id);

    if (BODY_SIZE(tlv) == 8){
        printf("Short hello received : source id is %lu\n", TLV_HELLO_ID_SOURCE(tlv));
    } else if (BODY_SIZE(tlv) == 16){
        dest = TLV_HELLO_ID_DEST(tlv);
        printf("Long hello received : source id is %lu, our id is %lu (%s)\n",
                    source, dest, dest == id ? "correct" : "incorrect");
    } else {
        printf("Invalid hello received.\n");
        return;
    }

    body_t hello = { 0 };
    hello.size = tlv_hello_long(&hello.content, dest, source);

    message_t message = { 0 };
    message.magic = 93;
    message.version = 2;
    message.body_length = htons(hello.size);
    message.body = &hello;

    if (send_message(neighbours, sock, &message) < 0) {
        perror("send message");
    }
}

#define TLV_NEIGHBOUR_PORT(tlv) ntohs(*(u_int32_t*)(tlv->content + HEADER_OFFSET + 16))

static void handle_neighbour(const body_t *tlv){
    short port = TLV_NEIGHBOUR_PORT(tlv);
    printf("Neighbour received : ip is \"%s\" and port is %hu\n", "TODO", port);
}

static void handle_data(const body_t *tlv){
    printf("DATA\n");
}

static void handle_ack(const body_t *tlv){
    printf("ACK\n");
}

static void handle_goaway(const body_t *tlv){
    printf("GO AWAY\n");
}

static void handle_warning(const body_t *tlv){
    printf("WARNING\n");
}

static void handle_unknown(const body_t *tlv){
    printf("UNKNOWN\n");
}

static void (*handles[NUMBER_TLV_TYPE + 1])(const body_t*) = {
    handle_pad1,
    handle_padn,
    handle_hello,
    handle_neighbour,
    handle_data,
    handle_ack,
    handle_goaway,
    handle_warning,
    handle_unknown
};

void handle_tlv(const body_t *tlv){
    do {
        if (BODY_TYPE(tlv) >= NUMBER_TLV_TYPE || BODY_TYPE(tlv) < 0){
            handles[NUMBER_TLV_TYPE](tlv);
        } else {
            handles[(int)BODY_TYPE(tlv)](tlv);
        }
    } while ((tlv = tlv->next) != NULL);
    printf("\n\n");
}
