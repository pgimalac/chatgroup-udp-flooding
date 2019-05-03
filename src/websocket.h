#ifndef __H_WEBSOCKET
#define __H_WEBSOCKET

#include <pthread.h>
#include <stdlib.h>

#include "structs/hashmap.h"

int httpport;
int websock;

list_t *clientsockets;
pthread_mutex_t clientsockets_mutex;

hashmap_t *webmessage_map;

int create_tcpserver(int port);

int handle_http();

int handle_ws(int);

int print_web(const u_int8_t *buffer, size_t len);

#endif
