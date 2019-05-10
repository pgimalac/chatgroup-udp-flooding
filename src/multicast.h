#include <sys/socket.h>

neighbour_t *multicast;

int init_multicast();
int hello_multicast(struct timeval *tv);
