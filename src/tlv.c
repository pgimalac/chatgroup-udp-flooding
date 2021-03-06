#include <stdio.h>
#include <string.h>

#include "flooding.h"
#include "network.h"
#include "tlv.h"

int tlv_pad1(u_int8_t **buffer) {
    *buffer = malloc(1);
    if (*buffer == NULL)
        return -1;

    **buffer = BODY_PAD1;

    return 1;
}

int tlv_padn(u_int8_t **buffer, u_int8_t n) {
    int size = HEADER_OFFSET + n;
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    (*buffer)[0] = BODY_PADN;
    (*buffer)[1] = n;
    memset(*buffer + HEADER_OFFSET, 0, n);

    return size;
}

int tlv_hello_short(u_int8_t **buffer, chat_id_t source) {
    int size = HEADER_OFFSET + sizeof(source);
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    (*buffer)[0] = BODY_HELLO;
    (*buffer)[1] = sizeof(source);

    memcpy(HEADER_OFFSET + *buffer, &source, sizeof(source));

    return size;
}

int tlv_hello_long(u_int8_t **buffer, chat_id_t source, chat_id_t dest) {
    int size = HEADER_OFFSET + sizeof(source) + sizeof(dest);
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    u_int8_t *offset = *buffer + HEADER_OFFSET;
    (*buffer)[0] = BODY_HELLO;
    (*buffer)[1] = sizeof(source) + sizeof(dest);
    memcpy(offset, &source, sizeof(source));
    memcpy(offset + sizeof(source), &dest, sizeof(dest));

    return size;
}

int tlv_neighbour(u_int8_t **buffer, const struct in6_addr *addr,
                  u_int16_t port) {
    int size = HEADER_OFFSET + sizeof(struct in6_addr) + sizeof(port);

    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    u_int8_t *offset = *buffer + HEADER_OFFSET;
    (*buffer)[0] = BODY_NEIGHBOUR;
    (*buffer)[1] = sizeof(struct in6_addr) + sizeof(port);
    memcpy(offset, addr, sizeof(struct in6_addr));
    memcpy(offset + sizeof(struct in6_addr), &port, sizeof(port));

    return size;
}

int tlv_data(u_int8_t **buffer, chat_id_t sender, u_int32_t nonce,
             u_int8_t type, const char *data, u_int8_t datalen) {

    u_int32_t true_size =
        datalen + sizeof(sender) + sizeof(nonce) + sizeof(type);
    if (true_size > 255)
        return -2;

    int size = HEADER_OFFSET + true_size;
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    u_int8_t *offset = *buffer + HEADER_OFFSET;
    (*buffer)[0] = BODY_DATA;
    (*buffer)[1] = (u_int8_t)true_size;
    memcpy(offset, &sender, sizeof(sender));
    offset += sizeof(sender);
    memcpy(offset, &nonce, sizeof(nonce));
    offset += sizeof(nonce);
    *offset = type;
    memcpy(offset + 1, data, datalen);

    return size;
}

int tlv_ack(u_int8_t **buffer, u_int64_t sender, nonce_t nonce) {
    int size = HEADER_OFFSET + sizeof(sender) + sizeof(nonce);
    (*buffer) = malloc(size);
    if (*buffer == NULL)
        return -1;

    u_int8_t *offset = *buffer + HEADER_OFFSET;
    (*buffer)[0] = BODY_ACK;
    (*buffer)[1] = sizeof(sender) + sizeof(nonce);
    memcpy(offset, &sender, sizeof(sender));
    memcpy(offset + sizeof(sender), &nonce, sizeof(nonce));

    return size;
}

int tlv_goaway(u_int8_t **buffer, u_int8_t code, const char *message,
               u_int8_t messagelen) {
    if (messagelen + sizeof(code) > 255)
        return -2;

    int size = HEADER_OFFSET + sizeof(code) + messagelen;
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    (*buffer)[0] = BODY_GO_AWAY;
    (*buffer)[1] = messagelen + sizeof(code);
    (*buffer)[2] = code;
    memcpy(*buffer + 3, message, messagelen);

    return size;
}

int tlv_warning(u_int8_t **buffer, const char *message, u_int8_t messagelen) {
    int size = HEADER_OFFSET + messagelen;
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    (*buffer)[0] = BODY_WARNING;
    (*buffer)[1] = messagelen;
    memcpy(*buffer + HEADER_OFFSET, message, messagelen);

    return size;
}
