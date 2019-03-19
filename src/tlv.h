#ifndef __H_TLV
#define __H_TLV

#include <stdlib.h>

#define BODY_PAD1 0
#define BODY_PADN 1
#define BODY_HELLO 2
#define BODY_NEIGHBOUR 3
#define BODY_DATA 4
#define BODY_ACK 5
#define BODY_GO_AWAY 6
#define BODY_WARNING 7

#define DATA_KNOWN 0

#define GO_AWAY_UNKNOWN 0
#define GO_AWAY_LEAVE 1
#define GO_AWAY_HELLO 2
#define GO_AWAY_BROKEN 3

int tlv_pad(char**);

int tlv_padn(char**, const u_int8_t);

int tlv_hello_short(char**, const u_int64_t);

int tlv_hello_long(char**, const u_int64_t , const u_int64_t);

int tlv_neighbour(char**, const char*, const u_int8_t , const u_int16_t);

int tlv_data(char**, const u_int64_t , const u_int32_t , const u_int8_t , const char*, const u_int8_t);

int tlv_ack(char**, const u_int64_t , const u_int32_t);

int tlv_goaway(char**, const u_int8_t , const char*, const u_int8_t);

int tlv_warning(char**, const char*, const u_int8_t);


#endif
