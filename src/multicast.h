#include <sys/socket.h>

neighbour_t *multicast;

int init_multicast();
int join_group_on_all_interfaces(int s);
int hello_multicast(struct timeval *tv);
