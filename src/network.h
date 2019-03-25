#ifndef __H_NETWORK
#define __H_NETWORK

#include <netinet/in.h>
#include <stdlib.h>

#include "types.h"
#include "utils.h"

int sock;
chat_id_t id;
neighbour_t *neighbours, *potential_neighbours;

int init_network();

size_t message_to_iovec(message_t *msg, struct iovec **iov);

int add_neighbour(char *hostname, char *service, neighbour_t**);

int send_message(neighbour_t *neighbour, int sock, message_t *msg);

int start_server(int port);

int recv_message(int sock, struct sockaddr_in6 *peer_addr, char *buf, size_t *buflen);

int bytes_to_message(const char *buf, size_t buflen, message_t *msg);

#endif
