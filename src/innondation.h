#include "types.h"

void hello_potential_neighbours(int sock);

int hello_neighbours(int sock, struct timeval *tv);

int update_hello (const chat_id_t *hello, size_t len,
                  struct sockaddr_in6 *addr);

int update_neighbours(const struct in6_addr *ip, u_int16_t port);
