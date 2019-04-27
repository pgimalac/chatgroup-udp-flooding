#include "tlv.h"
#include "network.h"

#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <stdio.h>

int tlv_pad(u_int8_t **buffer){
    *buffer = malloc(1);
    if (*buffer == NULL)
        return -1;

    **buffer = BODY_PAD1;

    return 1;
}

int tlv_padn(u_int8_t **buffer, u_int8_t n){
    int size = HEADER_OFFSET + n;
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    (*buffer)[0] = BODY_PADN;
    (*buffer)[1] = n;
    memset(*buffer + HEADER_OFFSET, 0, n);

    return size;
}

int tlv_hello_short(u_int8_t **buffer, chat_id_t source){
    int size = HEADER_OFFSET + sizeof(source);
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    (*buffer)[0] = BODY_HELLO;
    (*buffer)[1] = sizeof(source);

    memmove(HEADER_OFFSET + *buffer, &source, sizeof(source));

    return size;
}

int tlv_hello_long(u_int8_t **buffer, chat_id_t source, chat_id_t dest){
    int size = HEADER_OFFSET + sizeof(source) + sizeof(dest);
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    u_int8_t *offset = *buffer + HEADER_OFFSET;
    (*buffer)[0] = BODY_HELLO;
    (*buffer)[1] = sizeof(source) + sizeof(dest);
    memmove(offset, &source, sizeof(source));
    memmove(offset + sizeof(source), &dest, sizeof(dest));

    return size;
}

int tlv_neighbour(u_int8_t **buffer, const struct in6_addr *addr, u_int16_t port){
    int size = HEADER_OFFSET + sizeof(struct in6_addr) + sizeof(port);

    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    u_int8_t *offset = *buffer + HEADER_OFFSET;
    (*buffer)[0] = BODY_NEIGHBOUR;
    (*buffer)[1] = sizeof(struct in6_addr) + sizeof(port);
    memmove(offset, addr, sizeof(struct in6_addr));
    memmove(offset + sizeof(struct in6_addr), &port, sizeof(port));

    return size;
}

int tlv_data(u_int8_t **buffer,
             chat_id_t sender, nonce_t nonce,
             u_int8_t type, const char *data, u_int8_t datalen){
    u_int32_t true_size = datalen + sizeof(sender) + sizeof(nonce) + sizeof(type);
    if (true_size > 255)
        return -2;

    int size = HEADER_OFFSET + true_size;
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    u_int8_t *offset = *buffer + HEADER_OFFSET;
    (*buffer)[0] = BODY_DATA;
    (*buffer)[1] = (u_int8_t) true_size;
    memmove(offset, &sender, sizeof(sender));
    offset += sizeof(sender);
    memmove(offset, &nonce, sizeof(nonce));
    offset += sizeof(nonce);
    *offset = type;
    memmove(offset + 1, data, datalen);

    printf("TLV DATA SIZE %d\n", size);
    return size;
}

int tlv_ack(u_int8_t **buffer, u_int64_t sender, nonce_t nonce){
    int size = HEADER_OFFSET + sizeof(sender) + sizeof(nonce);
    (*buffer) = malloc(size);

    u_int8_t *offset = *buffer + HEADER_OFFSET;
    (*buffer)[0] = BODY_ACK;
    (*buffer)[1] = sizeof(sender) + sizeof(nonce);
    memmove(offset, &sender, sizeof(sender));
    memmove(offset + sizeof(sender), &nonce, sizeof(nonce));

    return size;
}

int tlv_goaway(u_int8_t **buffer, u_int8_t code,
               const char *message, u_int8_t messagelen){
    if (messagelen + sizeof(code) > 255)
        return -2;

    int size = HEADER_OFFSET + sizeof(code) + messagelen;
    *buffer = malloc(size);

    (*buffer)[0] = BODY_GO_AWAY;
    (*buffer)[1] = messagelen + sizeof(code);
    (*buffer)[2] = code;
    memmove(*buffer + 3, message, messagelen);

    return size;
}

int tlv_warning(u_int8_t **buffer, const char *message, u_int8_t messagelen){
    int size = HEADER_OFFSET + messagelen;
    *buffer = malloc(size);

    (*buffer)[0] = BODY_WARNING;
    (*buffer)[1] = messagelen;
    memmove(*buffer + HEADER_OFFSET, message, messagelen);

    return size;
}
