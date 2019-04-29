#ifndef __H_NETWORK
#define __H_NETWORK

#include <netinet/in.h>
#include <stdlib.h>

#include "types.h"
#include "utils.h"
#include "structs/hashset.h"

// the given buffer is NULL
#define BUFNULL -1
// the given buffer is too short
#define BUFSH -2
// the given size of the buffer is incoherent with the size of the message
#define BUFINC -3
// a tlv other than PAD1 is one byte long
#define TLVSH  -4
// the sum of all tlv is greater than the size of the buffer
#define SUMLONG -5

#define DEF_PMTU 1024

int sock;
chat_id_t id;
hashset_t *neighbours, *potential_neighbours;

int init_network();

size_t message_to_iovec(message_t *msg, struct iovec **iov);

neighbour_t *
new_neighbour(const unsigned char ip[sizeof(struct in6_addr)],
              unsigned int port, const neighbour_t *tutor);

int add_neighbour(const char *hostname, const char *service);

int send_message(int sock, message_t *msg, struct timeval *tv);

int start_server(int port);

int recv_message(int sock, struct sockaddr_in6 *peer_addr, u_int8_t *buf, size_t *buflen);

int bytes_to_message(const u_int8_t *buf, size_t buflen, neighbour_t*, message_t*);

void quit_handler(int sig);

#endif
