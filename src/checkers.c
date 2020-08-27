#include "network.h"
#include "tlv.h"
#include "types.h"
#include <stdio.h>
#include <string.h>

static int check_pad1(const u_int8_t *tlv) { return 1; }

static int check_padn(const u_int8_t *tlv) {
    u_int8_t len = tlv[1];
    for (int i = 2; i < len + 2; i++)
        if (tlv[i] != 0)
            return PADNO0;
    return HEADER_OFFSET + tlv[1];
}

static int check_hello(const u_int8_t *tlv) {
    if (tlv[1] != sizeof(chat_id_t) && tlv[1] != 2 * sizeof(chat_id_t))
        return HELLOSIZEINC;
    return HEADER_OFFSET + tlv[1];
}

static int check_neighbour(const u_int8_t *tlv) {
    if (tlv[1] != 18)
        return NEIGSIZEINC;
    return HEADER_OFFSET + tlv[1];
}

static int check_data(const u_int8_t *tlv) {
    if (tlv[1] < sizeof(chat_id_t) + sizeof(nonce_t) + 1)
        return DATASIZEINC;
    return HEADER_OFFSET + tlv[1];
}

static int check_ack(const u_int8_t *tlv) {
    if (tlv[1] != sizeof(chat_id_t) + sizeof(nonce_t))
        return ACKSIZEINC;
    return HEADER_OFFSET + tlv[1];
}

static int check_goaway(const u_int8_t *tlv) {
    if (tlv[1] == 0)
        return GOAWSIZEINC;
    return HEADER_OFFSET + tlv[1];
}

static int check_warning(const u_int8_t *tlv) { return HEADER_OFFSET + tlv[1]; }

static int check_unknown(const u_int8_t *tlv) { return HEADER_OFFSET + tlv[1]; }

static int (*checkers[NUMBER_TLV_TYPE + 1])(const u_int8_t *) = {
    check_pad1, check_padn,   check_hello,   check_neighbour, check_data,
    check_ack,  check_goaway, check_warning, check_unknown};

static int check_tlv_size(const u_int8_t *tlv) {
    if (tlv[0] < NUMBER_TLV_TYPE)
        return checkers[tlv[0]](tlv);
    return checkers[NUMBER_TLV_TYPE](tlv);
}

int check_message_size(const u_int8_t *buffer, int buflen) {
    if (buflen < 4)
        return BUFSH;

    u_int16_t body_length;
    memcpy(&body_length, buffer + 2, sizeof(body_length));
    body_length = ntohs(body_length);

    if (body_length + 4 > buflen)
        return BUFINC;
    buflen = body_length + 4;

    int i = 4, body_num = 0, rc;
    while (i < buflen) {
        i++;
        if (buffer[i - 1] != BODY_PAD1) {
            if (i >= buflen)
                return TLVSH;
            i += 1 + (u_int8_t)buffer[i];
        }
        body_num++;
    }

    if (i != buflen)
        return SUMLONG;

    i = 4;
    while (i < buflen) {
        rc = check_tlv_size(buffer + i);
        if (rc < 0)
            return rc;
        i += rc;
    }

    return body_num;
}
