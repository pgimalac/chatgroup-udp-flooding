#define _GNU_SOURCE

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/sha.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "base64.h"
#include "utils.h"
#include "websocket.h"

int pagelen = 0;
char page[8192];

int create_tcpserver(int port) {
    int rc, s, fd;
    struct sockaddr_in6 sin6 = { 0 };

    sin6.sin6_family = PF_INET6;
    sin6.sin6_port = htons(port);

    s = socket(AF_INET6, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return -1;
    }

    rc = bind(s, (struct sockaddr*)&sin6, sizeof(struct sockaddr_in6));
    if (rc < 0) {
        perror("bind");
        return -2;
    }

    rc = listen(s, 1024);
    if (rc < 0) {
        perror("listen");
        return -1;
    }

    fd = open("index.html", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    pagelen = read(fd, page, 8192);
    if (pagelen < 0) {
        perror("read");
        return -1;
    }

    close(fd);

    return s;
}

const char *NOT_FOUND = "HTTP/1.1 404 Not Found\n\r\n\r\nThis page don't exist";
const char *INVALID = "HTTP/1.1 400 Bas Request\n\r\n\r";
const char *STATUSLINE = "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\n";
const char *MAGICSTRINGWS = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const size_t MSWSL = strlen("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
const char *SWITPROTO = "HTTP/1.1 101 Switching Protocols\nUpgrade: websocket\nConnection: Upgrade\n";

int handle_http () {
    int rc, s;
    size_t len = 0, keylen;
    char buffer[4096], *ptr, *end;
    unsigned char *key, hash[20];
    unsigned char *h64;

    s = accept(websock, 0, 0);
    if (s < 0) {
        perror("accept");
        return 1;
    }

    printf("New web connection\n");

    memset(buffer, 0, 4096);
    len = 0;
    while ((rc = read(s, buffer + len, 4096 - len)) > 0) {
        len += rc;
        if (memmem(buffer, 4096, "\r\n\r\n", 4))
            break;
    }

    if (rc < 0) {
        perror("read");
        close(s);
        return -1;
    }

    write(1, buffer, len);

    // empty request
    if (len == 0) {
        close(s);
        return 0;
    }

    // web page
    if (memcmp("GET / HTTP/1.1", buffer, 14) == 0) {
        write(s, STATUSLINE, strlen(STATUSLINE));

        char tmp[250];
        rc = sprintf(tmp, "Content-Length: %d\n", pagelen);
        write(s, tmp, rc);
        write(s, "\r\n\r\n", 4);
        write(s, page, pagelen);

        close(s);
        return 0;
    }

    // web socket interface
    if (memcmp("GET /ws HTTP/1.1", buffer, 14) == 0) {
        ptr = memmem(buffer, len, "Sec-WebSocket-Key: ", 19);
        if (!ptr) {
            write(s, INVALID, strlen(INVALID));
            close(s);
            return 1;
        }

        end = memchr(ptr, '\r', len - (ptr - buffer));
        if (!end) {
            write(s, INVALID, strlen(INVALID));
            close(s);
            return 1;
        }

        printf("0:%x 9:%x a:%x z:%x A:%x Z:%x\n", '0', '9', 'a', 'z', 'A', 'Z');
        keylen = end - ptr - 19;
        key = alloca(keylen + MSWSL);
        memcpy(key, ptr + 19, keylen);

        printf("\n\n");
        write(STDOUT_FILENO, key, keylen);
        printf("\n\n");

        printf("keylen %lu, magic %lu, %lu\n", keylen, MSWSL, keylen + MSWSL);
        print_bytes((char*)key, keylen);
        memcpy(key + keylen, MAGICSTRINGWS, MSWSL);
        print_bytes((char*)key, keylen + MSWSL);

        printf("\n\n");
        rc = write(STDOUT_FILENO, key, keylen + MSWSL);
        if (rc < 0) {
            perror("write");
        }
        printf("\n\n");

        SHA1(key, keylen + MSWSL, hash);
        h64 = base64_encode(hash, 20, &keylen);


        write(s, SWITPROTO, strlen(SWITPROTO));
        write(s, "Sec-WebSocket-Accept: ", 22);
        write(s, h64, keylen);
        write(s, "\n\r\n\r\n", 5);

        free(h64);

        close(s);

        return 0;
    }

    write(s, NOT_FOUND, strlen(NOT_FOUND));
    close(s);

    return 0;
}
