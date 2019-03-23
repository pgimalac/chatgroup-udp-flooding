#ifndef __H_TLV
#define __H_TLV

#include <stdlib.h>
#include <netinet/in.h>

#include "types.h"

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

int tlv_pad(char **buffer);

int tlv_padn(char **buffer, u_int8_t n);

int tlv_hello_short(char **buffer, chat_id_t source);

int tlv_hello_long(char **buffer, chat_id_t source, chat_id_t dest);

int tlv_neighbour(char **buffer, const struct in6_addr*, u_int16_t port);

int tlv_data(char **buffer, u_int64_t sender, u_int32_t nonce,
             u_int8_t type, const char *data, u_int8_t datalen);

int tlv_ack(char **buffer, chat_id_t sender, nonce_t nonce);

int tlv_goaway(char **buffer, u_int8_t code, const char *message, u_int8_t messagelen);

int tlv_warning(char **buffer, const char *message, const u_int8_t messagelen);


#endif
