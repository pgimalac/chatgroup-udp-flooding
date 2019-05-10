#ifndef __H_TLV
#define __H_TLV

#include <stdlib.h>
#include <netinet/in.h>

#include "types.h"
#include "structs/hashmap.h"

#define HEADER_OFFSET 2

#define BODY_PAD1 0
#define BODY_PADN 1
#define BODY_HELLO 2
#define BODY_NEIGHBOUR 3
#define BODY_DATA 4
#define BODY_ACK 5
#define BODY_GO_AWAY 6
#define BODY_WARNING 7

#define DATA_KNOWN 0
#define DATA_FRAG 220

#define NUMBER_TLV_TYPE 8

#define GO_AWAY_UNKNOWN 0
#define GO_AWAY_LEAVE 1
#define GO_AWAY_HELLO 2
#define GO_AWAY_BROKEN 3

#define PADNO0 -100
#define HELLOSIZEINC -101
#define NEIGSIZEINC -102
#define DATASIZEINC -103
#define ACKSIZEINC -104
#define GOAWSIZEINC -105
#define WARNSIZEINC -106

#define TIMEVAL_PMTU 30
#define TIMEVAL_DEC_PMTU 5
hashmap_t *pmtu_map;

int tlv_pad1(u_int8_t **buffer);
int tlv_padn(u_int8_t **buffer, u_int8_t n);
int tlv_hello_short(u_int8_t **buffer, chat_id_t source);
int tlv_hello_long(u_int8_t **buffer, chat_id_t source, chat_id_t dest);
int tlv_neighbour(u_int8_t **buffer, const struct in6_addr*, u_int16_t port);
int tlv_data(u_int8_t **buffer, u_int64_t sender, u_int32_t nonce, u_int8_t type, const char *data, u_int8_t datalen);
int tlv_ack(u_int8_t **buffer, chat_id_t sender, nonce_t nonce);
int tlv_goaway(u_int8_t **buffer, u_int8_t code, const char *message, u_int8_t messagelen);
int tlv_warning(u_int8_t **buffer, const char *message, const u_int8_t messagelen);

void handle_tlv(const body_t *tlv, neighbour_t *);
void handle_invalid_message(int rc, neighbour_t *n);
int check_message_size(const u_int8_t* buffer, int buflen);

int push_tlv(body_t *tlv, neighbour_t *dst);
message_t *pull_message();
int pmtu_discovery(body_t *tlv, neighbour_t *dst);
int decrease_pmtu();

#endif
