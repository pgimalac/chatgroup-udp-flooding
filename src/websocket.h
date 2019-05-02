int httpport;
int websock;

list_t *clientsockets;
hashmap_t *webmessage_map;

int create_tcpserver(int port);

int handle_http();

int handle_ws();

int print_web(const uint8_t *buffer, size_t len);
