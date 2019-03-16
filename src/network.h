#include <sys/socket.h>
#include <netinet/in.h>

chat_id_t id;
neighbour_t *neighbours;

int init_network();

size_t
message_to_iovec(message_t *msg, struct iovec **iov, ssize_t len);

int
add_neighbour(char *hostname, char *service, neighbour_t **neighbour);

int
send_message(neighbour_t *neighbour, int sock, message_t *msg, size_t nb_body);

int
recv_message(int sock, struct in6_addr *addr, char *out, size_t *buflen);

message_t * bytes_to_message(void *buf, size_t buflen);

int
start_server(int port);
