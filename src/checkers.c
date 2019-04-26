#include "tlv.h"
#include "types.h"
#include "network.h"

static int check_pad1(const char *tlv){
    return 1;
}

static int check_padn(const char *tlv){
    u_int8_t len = (u_int8_t)tlv[1];
    for (int i = 2; i < len + 2; i++)
        if (tlv[i] != 0)
            return PADNO0;
    return HEADER_OFFSET + (u_int8_t)tlv[1];
}

static int check_hello(const char *tlv){
    if (tlv[1] != sizeof(chat_id_t) && tlv[1] != 2 * sizeof(chat_id_t))
        return HELLOSIZEINC;
    return HEADER_OFFSET + (u_int8_t)tlv[1];
}

static int check_neighbour(const char *tlv){
    if (tlv[1] != 18)
        return NEIGSIZEINC;
    return HEADER_OFFSET + (u_int8_t)tlv[1];
}

static int check_data(const char *tlv){
    if ((u_int8_t)tlv[1] < sizeof(chat_id_t) + sizeof(nonce_t) + 1)
        return DATASIZEINC;
    return HEADER_OFFSET + (u_int8_t)tlv[1];
}

static int check_ack(const char *tlv){
    if ((u_int8_t)tlv[1] != sizeof(chat_id_t) + sizeof(nonce_t))
        return ACKSIZEINC;
    return HEADER_OFFSET + (u_int8_t)tlv[1];
}

static int check_goaway(const char *tlv){
    if (tlv[1] == 0)
        return GOAWSIZEINC;
    return HEADER_OFFSET + (u_int8_t)tlv[1];
}

static int check_warning(const char *tlv){
    return HEADER_OFFSET + (u_int8_t)tlv[1];
}

static int check_unknown(const char *tlv){
    return HEADER_OFFSET + (u_int8_t)tlv[1];
}

static int (*checkers[NUMBER_TLV_TYPE + 1])(const char*) = {
    check_pad1,
    check_padn,
    check_hello,
    check_neighbour,
    check_data,
    check_ack,
    check_goaway,
    check_warning,
    check_unknown
};

int check_tlv_size(const char *tlv){
    if (tlv[0] < NUMBER_TLV_TYPE && tlv[0] >= 0)
        return checkers[(int)tlv[0]](tlv);
    return checkers[NUMBER_TLV_TYPE](tlv);
}
