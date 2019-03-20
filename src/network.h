#ifndef __H_NETWORK
#define __H_NETWORK

#include <netinet/in.h>
#include <stdlib.h>

#include "types.h"
#include "utils.h"


chat_id_t id;
neighbour_t *neighbours;

int init_network();
size_t message_to_iovec(message_t*, struct iovec **, ssize_t);
int add_neighbour(char*, char*, neighbour_t**);
int send_message(neighbour_t*, int, message_t*, size_t);
int start_server(int);
int recv_message(int, struct in6_addr*, char*, size_t*);
message_t * bytes_to_message(const char*, const size_t);

#endif
