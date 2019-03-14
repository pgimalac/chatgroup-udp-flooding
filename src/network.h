chat_id_t id;
neighbour_t *neighbours;

int init_network();

struct iovec *
message_to_iovec(message_t *msg, size_t *len);
