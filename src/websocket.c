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
#include <errno.h>

#include "base64.h"
#include "utils.h"
#include "structs/list.h"
#include "structs/hashmap.h"
#include "flooding.h"
#include "interface.h"
#include "websocket.h"

int pagelen = 0;
char page[16384];

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

    int opt = 1;
    rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    if (rc < 0){
        perror("setsockopt");
        return -3;
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

    pagelen = read(fd, page, 16384);
    int err = errno;
    close(fd);
    if (pagelen < 0) {
        perrorbis(err, "read");
        return -1;
    }

    return s;
}

const char *NOT_FOUND = "HTTP/1.1 404 Not Found\r\n\r\nThis page don't exist";
const char *INVALID = "HTTP/1.1 400 Bad Request\r\n\r\n";
const char *STATUSLINE = "HTTP/1.1 200 OK\r\n";
const char *MAGICSTRINGWS = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const size_t MSWSL = strlen("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
const char *SWITPROTO = "HTTP/1.1 101 Switching Protocols\r\n"
    "Upgrade: websocket\r\nConnection: Upgrade\r\n";

static int not_found(int s) {
    write(s, NOT_FOUND, strlen(NOT_FOUND));
    close(s);
    return 0;
}

static int bad_request(int s) {
    write(s, INVALID, strlen(INVALID));
    fprintf(stderr, "Bad request\n");
    close(s);
    return 0;
}

static int get_static_file(int s, const char *path, size_t len) {
    int fd, rc;
    char buffer[1024];
    char *npath = calloc(len + 1, 1);
    memcpy(npath, path, len);

    char *fp = calloc(len + strlen(tmpdir) + 6, 1);
    sprintf(fp, "/tmp/%s%s", tmpdir, npath);

    char *pt = 0;
    for (char *p = memchr(path, '.', len); p && (pt = p);
         p = memchr(p + 1, '.', len - (p - path))) {
    }

    // file has no extention, not supppose to happend
    // ignore this situation
    if (!pt) {
        free(npath);
        free(fp);
        return not_found(s);
    }

    char *content_type;
    if (memcmp(pt, ".png", len - (pt - path)) == 0) {
        content_type = "Content-Type: image/png\r\n";
    } else if (memcmp(pt, ".jpg", len - (pt - path)) == 0) {
        content_type = "Content-Type: image/jpg\r\n";
    } else if (memcmp(pt,".gif", len - (pt - path)) == 0) {
        content_type = "Content-Type: image/gif\r\n";
    } else if (memcmp(pt,".svg", len - (pt - path)) == 0) {
        content_type = "Content-Type: image/svg\r\n";
    } else {
        content_type = "Content-Type: text/html\r\n";
    }

    cprint(0, "Try to load file %s.\n", fp);
    fd = open(fp, O_RDONLY);
    int err = errno;

    free(npath);
    free(fp);

    if (fd < 0) {
        perrorbis(err, "open");
        return not_found(s);
    }

    write(s, STATUSLINE, strlen(STATUSLINE));
    write(s, content_type, strlen(content_type));
    write(s, "\r\n", 2);

    while ((rc = read(fd, buffer, 1024)) > 0)
        write(s, buffer, rc);

    close(s);
    return 0;
}

static int get_index(int s) {
    write(s, STATUSLINE, strlen(STATUSLINE));
    write(s, "Content-Type: text/html; charset=utf-8\r\n", 40);

    char tmp[250];
    int rc = sprintf(tmp, "Content-Length: %d\r\n\r\n", pagelen);
    write(s, tmp, rc);
    write(s, page, pagelen);
    close(s);
    return 0;
}

static int get_ws(int s, const char *buffer, size_t len) {
    unsigned char *key, hash[20], *h64;
    char *ptr, *end;
    size_t keylen;

    // web socket interface
    if (memcmp("GET /ws HTTP/1.1", buffer, 14))
        return not_found(s);
    // check Connection
    if (!memmem(buffer, len, "Upgrade: websocket", 18))
        return bad_request(s);

    ptr = memmem(buffer, len, "Sec-WebSocket-Key: ", 19);
    if (!ptr) return bad_request(s);

    end = memchr(ptr, '\r', len - (ptr - buffer));
    if (!end) return bad_request(s);

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

int handle_http () {
    int rc, s, i;
    size_t len = 0;
    char buffer[4096];

    s = accept(websock, 0, 0);
    if (s < 0) {
        perror("accept");
        return 1;
    }

    cprint(0, "New web connection\n");

    memset(buffer, 0, 4096);
    len = 0;
    for (i = 0; i < 100 && (rc = read(s, buffer + len, 4096 - len)) > 0; i++) {
        len += rc;
        if (memmem(buffer, len, "\r\n\r\n", 4))
            break;
    }

    if (rc < 0) {
        perror("read");
        close(s);
        return -1;
    }

    cprint(0, "%*s", len, buffer);

    // empty request
    if (len <= 6) {
        close(s);
        return 0;
    }

    char *sp1, *sp2;
    sp1 = memchr(buffer, ' ', len);
    if (!sp1 || sp1[1] != '/') return bad_request(s);

    sp2 = memchr(sp1 + 1, ' ', len - (sp1 - buffer));
    if (!sp2) return bad_request(s);

    if (memcmp(sp2 + 1, "HTTP/1.1", 8)) {
        cprint(STDERR_FILENO, "no HTTP/1.1\n");
        return bad_request(s);
    }

    switch (sp1[2]) {
    case ' ':
        return get_index(s);
        break;

    case 'w':
        return get_ws(s, buffer, len);
        break;

    default:
        return get_static_file(s, sp1 + 1, sp2 - sp1 - 1);
    }
}

#define FINBIT (1 << 7)
#define MSKBIT (1 << 7)

#define OPCONT 0x00
#define OPTXT 0x01
#define OPBIN 0x02
#define OPCLOSE 0x08
#define OPPING 0x09
#define OPPONG 0x0a

static const int png_sig_len = 8;
static const int8_t png_sig[] = { 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a };

static const int gif_sig_len[] = {6, 6};
static const int8_t gif_sig[] =
    {
     0x47, 0x49, 0x46, 0x38, 0x37, 0x61,
     0x47, 0x49, 0x46, 0x38, 0x39, 0x61
    };

static const int jpg_sig_len[] = {4, 12, 4};
static const int8_t jpg_sig[] =
    { 0xFF, 0xD8, 0xFF, 0xDB,
      0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
      0xFF, 0xD8, 0xFF, 0xEE
    };

static uint8_t file_type(const int8_t *buffer, size_t len) {
    if (len < 4) return 0;

    if (memcmp(buffer, png_sig, png_sig_len) == 0) {
        return 4;
    }

    for (int i = 0, offset = 0; i < 2; offset += gif_sig_len[i++]) {
        if (memcmp(buffer, gif_sig + offset, gif_sig_len[i]) == 0)
            return 2;
    }

    for (int i = 0, offset = 0; i < 2; offset += jpg_sig_len[i++]) {
        if (memcmp(buffer, jpg_sig + offset, jpg_sig_len[i]) == 0)
            return 3;
    }

    return -1;
}

typedef struct fragws {
    uint8_t opcode;
    uint8_t offset;
    int8_t *buffer;
    size_t buflen;
} fragws_t;


static int send_pong (int s, const int8_t *payload, size_t buflen) {
    int rc;
    uint8_t frame[1024];
    uint32_t mask = random_uint32();
    size_t len, i, j, count = 0,
        size = (buflen < 125 ? 1 : buflen / 125);

    cprint(0, "Ping received, send pong.\n");

    for (i = 0; i < size; i++) {
        memset(frame, 0, 1024);
        frame[0] = i == 0 ? OPPONG : OPCONT;
        frame[1] = MSKBIT;

        len = buflen - count > 125 ? 125 : buflen - count;
        frame[1] ^= len;

        mask = random_uint32();
        memcpy(frame + 2, &mask, 4);

        for (j = 0; j < len; j++) {
            frame[j + 6] = payload[j] ^ frame[2 + (j % 4)];
        }

        // last frame FIN bit
        if (i == size - 1)
            frame[0] ^= FINBIT;

        rc = write(s, frame, 2 + 4 + len);
        if (rc < 0) {
            cperror("write");
            return 0;
        }
    }

    cprint(0, "Pong sended.\n");

    return 0;
}

int handle_ws(int s) {
    int rc, status = 0, type;
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
        cprint(0, "Connection closed by web page\n");
        close(s);
        return -1;
    }

    fin = opcode & FINBIT;
    opcode &= 0x0f;

    memset(len, 0, 8);
    rc = read(s, len, 1);
    if (rc < 0) {
        cperror("read");
        return -1;
    }

    if (rc == 0) {
        cprint(0, "Connection closed by web page\n");
        close(s);
        return -1;
    }

    mask = len[0] & MSKBIT;
    memset(maskkey, 0, 4);

    cprint(0, "web message received fin = %d, opcode = %d, mask = %d\n",
           fin ? 1 : 0, opcode, mask ? 1 : 0);

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
        cperror("read");
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
        if (opcode == OPCONT) {
            cprint(STDERR_FILENO, "continue frame but there is nothing to continue\n");
            close(s);
            free(payload);
            free(decoded);
            return -1;
        }

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
        case OPTXT: //text
            cprint(STDOUT_FILENO, "%*s\n", frag->buflen, frag->buffer);
            handle_input((char*)frag->buffer, frag->buflen);
            break;

        case OPBIN: //bin
            type = file_type(frag->buffer, frag->buflen);
            if (type >= 255) {
                cprint(0, "Received unknown file type from web app. Assume this is text.\n");
                send_data(0, (char*)frag->buffer, frag->buflen);
                print_file(0, (u_int8_t*)frag->buffer, frag->buflen);
            } else {
                send_data(type, (char*)frag->buffer, frag->buflen);
                print_file(type, (u_int8_t*)frag->buffer, frag->buflen);
            }

            break;

        case OPCLOSE: // close
            // send close
            if (frag->buflen) {
                uint16_t code = ntohs(*((uint16_t*)frag->buffer));
                cprint(0, "close code %u\n", code);
            }

            if (frag->buflen > 2) {
                cprint(0, "closing message: %*s\n",
                       frag->buflen - 2, frag->buffer + 2);
            }

            status = -1;
            close(s);
            break;

        case OPPING: //ping
            send_pong(s, frag->buffer, frag->buflen);
            break;

        case OPPONG: //pong
            break;
        }
    }

    if (fin || opcode == OPCLOSE) {
        free(frag->buffer);
        hashmap_remove(webmessage_map, &s, 1, 1);
    }

    free(decoded);
    free(payload);

    cprint(0, "done.\n");
    return status;
}

int print_web(const uint8_t *buffer, size_t buflen) {
    int s, rc;
    list_t *l;
    uint8_t frame[1024];
    uint32_t mask;

    size_t len, i, j, count = 0;

    for (i = 0, count = 0; count < buflen; i++) {
        memset(frame, 0, 1024);
        frame[0] = i == 0 ? OPTXT : OPCONT;
        frame[1] = MSKBIT;

        len = buflen - count > 125 ? 125 : buflen - count;
        frame[1] ^= len;

        mask = random_uint32();
        memcpy(frame + 2, &mask, 4);

        for (j = 0; j < len; j++) {
            frame[j + 6] = buffer[j + count] ^ frame[2 + (j % 4)];
        }
        count += len;

        // last frame FIN bit
        if (len < 125)
            frame[0] ^= FINBIT;

        //print_bytes((char*)frame, 2 + 4 + len);

        for (l = clientsockets; l; l = l->next) {
            s = *((int*)l->val);
            rc = write(s, frame, 2 + 4 + len);
            if (rc < 0) {
                cperror("write");
                return -1;
            }
        }
    }

    return 0;
}
