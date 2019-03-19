#ifndef __H_NETWORK
#define __H_NETWORK

#include <netinet/in.h>
#include <stdlib.h>

#include "types.h"
#include "utils.h"


chat_id_t id;
neighbour_t *neighbours;

int init_network();
size_t message_to_iovec(message_t*, struct iovec **, const ssize_t);
int add_neighbour(const char*, const char*, neighbour_t**);
int send_message(neighbour_t*, const int, message_t*, const size_t);
int start_server(const unsigned short);
int recv_message(const int, struct in6_addr*, char*, size_t*);
message_t * bytes_to_message(void*, size_t);
#endif

