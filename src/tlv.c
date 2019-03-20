#include "tlv.h"

#include <string.h>
#include <endian.h>

#define HEADER_OFFSET 2

int tlv_pad(char **buffer){
    *buffer = malloc(1);
    if (*buffer == NULL)
        return -1;

    **buffer = BODY_PAD1;

    return 1;
}

int tlv_padn(char **buffer, const u_int8_t n){
    int size = HEADER_OFFSET + n;
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    (*buffer)[0] = BODY_PADN;
    (*buffer)[1] = n;
    memset(*buffer + HEADER_OFFSET, 0, n);

    return size;
}

int tlv_hello_short(char **buffer, const u_int64_t source){
    u_int64_t n_source = htobe64(source);

    int size = HEADER_OFFSET + sizeof(n_source);
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    (*buffer)[0] = BODY_HELLO;
    (*buffer)[1] = sizeof(source);
    memmove(HEADER_OFFSET + *buffer, &n_source, sizeof(n_source));

    return size;
}

int tlv_hello_long(char **buffer, const u_int64_t source, const u_int64_t dest){
    u_int64_t n_source = htobe64(source);
    u_int64_t n_dest = htobe64(dest);

    int size = HEADER_OFFSET + sizeof(n_source) + sizeof(n_dest);
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    char *offset = *buffer + HEADER_OFFSET;
    (*buffer)[0] = BODY_HELLO;
    (*buffer)[1] = sizeof(source);
    memmove(offset, &n_source, sizeof(n_source));
    memmove(offset + sizeof(source), &n_dest, sizeof(n_dest));

    return size;
}

int tlv_neighbour(char **buffer, const char *addr, const u_int8_t addrlen, const u_int16_t port){
    static const u_int8_t IP_MAX_SIZE = 16;
    u_int16_t n_port = htobe16(port);
    if (addrlen > IP_MAX_SIZE)
        return -2;

    int size = HEADER_OFFSET + IP_MAX_SIZE + sizeof(n_port);
    *buffer = malloc(size);
    if (*buffer == NULL)
        return -1;

    char *offset = *buffer + HEADER_OFFSET;
    (*buffer)[0] = BODY_NEIGHBOUR;
    (*buffer)[1] = IP_MAX_SIZE + sizeof(n_port);
    memmove(offset, addr, addrlen);
    memset(offset + addrlen, 0, IP_MAX_SIZE - addrlen);
    memmove(offset + IP_MAX_SIZE, &n_port, sizeof(n_port));

    return size;
}

int tlv_data(char **buffer, const u_int64_t sender, const u_int32_t nonce, const u_int8_t type, const char *data, const u_int8_t datalen){
    u_int64_t n_sender = htobe64(sender);
    u_int32_t n_nonce = htobe32(nonce);
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

int tlv_ack(char **buffer, const u_int64_t sender, const u_int32_t nonce){
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

int tlv_goaway(char **buffer, const u_int8_t code, const char *message, const u_int8_t messagelen){
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

int tlv_warning(char **buffer, const char *message, const u_int8_t messagelen){
    int size = HEADER_OFFSET + messagelen;
    *buffer = malloc(size);

    (*buffer)[0] = BODY_WARNING;
    (*buffer)[1] = messagelen;
    memmove(*buffer + HEADER_OFFSET, message, messagelen);

    return size;
}
