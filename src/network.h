chat_id_t id;
neighbour_t *neighbours;

int init_network();

size_t
message_to_iovec(message_t *msg, struct iovec **iov, ssize_t len);

int
add_neighbour(char *hostname, char *service,
              neighbour_t **neighbour);

int
send_message(neighbour_t *neighbour, int sock,
             message_t *msg, size_t nb_body);

int
start_server(int port);
