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
#include <assert.h>

#include "base64.h"
#include "utils.h"
#include "list.h"
#include "hashmap.h"
#include "flooding.h"
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
        if (memmem(buffer, len, "\r\n\r\n", 4))
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
        // check Connection
        if (!memmem(buffer, len, "Upgrade: websocket", 18)) {
            write(s, INVALID, strlen(INVALID));
            fprintf(stderr, "Invalid request\n");
            close(s);
        }

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

        keylen = end - ptr - 19;
        key = alloca(keylen + MSWSL);
        memcpy(key, ptr + 19, keylen);
        memcpy(key + keylen, MAGICSTRINGWS, MSWSL);

        SHA1(key, keylen + MSWSL, hash);
        h64 = base64_encode(hash, 20, &keylen);

        write(s, SWITPROTO, strlen(SWITPROTO));
        write(s, "Sec-WebSocket-Accept: ", 22);
        write(s, h64, keylen);
        write(s, "\r\n\r\n", 4);

        free(h64);

        int *ss = malloc(sizeof(int));
        *ss = s;
        list_add(&clientsockets, ss);

        return 0;
    }

    write(s, NOT_FOUND, strlen(NOT_FOUND));
    close(s);

    return 0;
}

typedef struct fragws {
    uint8_t opcode;
    uint8_t offset;
    int8_t *buffer;
    size_t buflen;
} fragws_t;

int handle_ws(int s) {
    int rc, status = 0;
    uint8_t fin, opcode, mask, len[8], maskkey[4];
    int8_t *decoded, *payload, *buffer;
    int64_t payloadlen = 0;
    fragws_t *frag;

    rc = read(s, &opcode, 1);
    if (rc < 0) {
        perror("read");
        return -1;
    }

    if (rc == 0) {
        printf("Connection closed by web page\n");
        close(s);
        return -1;
    }

    fin = (opcode >> 7) & 1;
    opcode &= 0x0f;

    memset(len, 0, 8);
    rc = read(s, len, 1);
    if (rc < 0) {
        perror("read");
        return -1;
    }

    if (rc == 0) {
        printf("Connection closed by web page\n");
        close(s);
        return -1;
    }

    mask = (len[0] >> 7) & 1;
    memset(maskkey, 0, 4);

    printf("web message received fin = %d, opcode = %02hhx, mask = %d\n",
           fin, opcode, mask);

    switch (len[0] & 0x7f) {
    case 126:
        read(s, len, 2);
        payloadlen = ntohs(*((uint16_t*)len));
        break;

    case 127:
        read(s, len, 8);
        payloadlen = ntohs(*((uint64_t*)len));
        break;

    default:
        payloadlen = len[0] & 0x7f;
    }

    if (mask) {
        read(s, maskkey, 4);
    }

    payload = malloc(payloadlen);
    rc = read(s, payload, payloadlen);
    if (rc < 0) {
        perror("read");
        free(payload);
        return -1;
    }

    if (rc == 0) {
        close(s);
        return 0;
    }

    if (rc < payloadlen) {
        return -1;
    }

    decoded = malloc(payloadlen);
    for(int64_t i = 0; i < payloadlen; i++)
        decoded[i] = payload[i] ^ maskkey[i % 4];

    frag = hashmap_get(webmessage_map, &s);
    if (!frag) {
        assert(opcode != 0);
        frag = malloc(sizeof(fragws_t));
        frag->opcode = opcode;
        frag->offset = 0;
        frag->buflen = 0;
        frag->buffer = 0;
        hashmap_add(webmessage_map, &s, frag);
    }

    buffer = malloc(frag->buflen + payloadlen);
    memcpy(buffer, frag->buffer, frag->buflen);
    memcpy(buffer + frag->buflen, decoded, payloadlen);
    free(frag->buffer);
    frag->buffer = buffer;
    frag->buflen += payloadlen;

    if (fin) {
        switch (frag->opcode) {
        case 0x01: //text
            write(1, frag->buffer, frag->buflen);
            printf("\n");

            send_data((char*)frag->buffer, frag->buflen);
            break;

        case 0x02: //bin
            break;

        case 0x08: // close
            // send close
            if (frag->buflen) {
                uint16_t code = ntohs(*((uint16_t*)frag->buffer));
                printf("close code %u\n", code);
            }

            if (frag->buflen > 2) {
                printf("closing message:\n");
                write(1, frag->buffer + 2, frag->buflen - 2);
                printf("\n");
            }

            status = -1;
            close(s);
            break;

        case 0x09: //ping
            break;

        case 0x0A: //pong
            break;
        }
    }

    if (fin || opcode == 0x08) {
        free(frag->buffer);
        hashmap_remove(webmessage_map, &s, 1, 1);
    }

    free(decoded);
    free(payload);

    printf("done.\n");
    return status;
}

int send_ping (int s) {
    uint8_t frame[1024];
    uint32_t mask = random_uint32();
    uint64_t payload = random_uint64();

    memset(frame, 0, 1024);
    frame[0] = 0x09;
    frame[1] = 0x80 ^ 8;
    memcpy(frame + 2, &mask, 4);
    memcpy(frame + 6, &payload, 8);

    for (int i = 0; i < 8; i++)
        frame[i + 6] ^= frame[2 + i % 4];

    write(s, frame, 8 + 4 + 2);

    return 0;
}

int print_web(const uint8_t *buffer, size_t buflen) {
    int s, rc;
    list_t *l;
    uint8_t frame[1024];
    uint32_t mask;

    size_t len, i, j, count = 0, size = (buflen < 125 ? 1 : buflen / 125);

    for (i = 0; i < size; i++) {
        memset(frame, 0, 1024);
        frame[0] = i == 0 ? 0x01 : 0x00;
        frame[1] = 0x80;

        len = buflen - count > 125 ? 125 : buflen - count;
        frame[1] ^= len;

        mask = random_uint32();
        memcpy(frame + 2, &mask, 4);

        for (j = 0; j < len; j++) {
            frame[j + 6] = buffer[j] ^ frame[2 + (j % 4)];
        }

        // last frame FIN bit
        if (i == size - 1)
            frame[0] ^= 0x80;

        //print_bytes((char*)frame, 2 + 4 + len);

        for (l = clientsockets; l; l = l->next) {
            s = *((int*)l->val);
            send_ping(s);
            return 0;
            rc = write(s, frame, 2 + 4 + len);
            if (rc < 0) {
                perror("write");
                return -1;
            }
        }
    }

    printf("sended\n");

    return 0;
}
