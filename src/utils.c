#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <readline/readline.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "interface.h"
#include "tlv.h"
#include "utils.h"

static int random_fd = -1;

void init_random() {
    random_fd = open("/dev/urandom", O_RDONLY);
    srand(time(0));
}

void *voidndup(const void *o, int n) {
    if (n <= 0)
        return NULL;
    void *cpy = malloc(n);

    if (cpy != NULL)
        memcpy(cpy, o, n);

    return cpy;
}

static void random_buffer(u_int8_t *buffer, int size) {
    int rc = -1;
    if (random_fd != -1)
        rc = read(random_fd, buffer, size);
    if (rc < size)
        for (int i = 0; i < size; i++)
            buffer[size] = rand();
}

u_int64_t random_uint64() {
    u_int64_t ret;
    random_buffer((u_int8_t *)&ret, sizeof(ret));
    return ret;
}

u_int32_t random_uint32() {
    u_int32_t ret;
    random_buffer((u_int8_t *)&ret, sizeof(ret));
    return ret;
}

unsigned int hash_neighbour_data(const u_int8_t ip[16], u_int16_t port) {
    unsigned int hash = 5381;
    for (int i = 0; i < 16; i++)
        hash = ((hash << 5) + hash) + ip[i] + port;
    return hash;
}

unsigned int hash_key(const char *buffer, int keylen) {
    unsigned int hash = 5381;

    for (int i = 0; i < keylen; i++)
        hash = ((hash << 5) + hash) + buffer[i];

    return hash;
}

void free_message(message_t *msg) {
    if (!msg)
        return;

    body_t *p, *b;
    p = msg->body;

    while (p != NULL) {
        b = p;
        p = p->next;

        free(b->content);
        free(b);
    }

    free(msg);
}

message_t *create_message(u_int8_t m, u_int8_t v, u_int16_t s, body_t *b,
                          neighbour_t *n) {
    message_t *message = malloc(sizeof(message_t));

    if (message) {
        message->magic = m;
        message->version = v;
        message->body_length = s;
        message->body = b;
        message->dst = n;
    }

    return message;
}

char *strappl(char *str1, ...) {
    if (!str1)
        return NULL;

    va_list ap;
    va_start(ap, str1);

    int *tmp = alloca(sizeof(int));
    *tmp = strlen(str1);
    list_t *head = list_init(tmp, NULL), *tail = head;
    int l = *tmp + 1;
    char *st;
    while ((st = va_arg(ap, char *))) {
        tmp = alloca(sizeof(int));
        *tmp = strlen(st);
        l += *tmp;
        tail->next = list_init(tmp, NULL);
        tail = tail->next;
    }
    va_end(ap);

    char *buff = malloc(sizeof(char) * l);
    va_start(ap, str1);
    l = 0;
    st = str1;
    do {
        strcpy(buff + l, st);
        l += *(int *)head->val;
        tail = head;
        head = head->next;
        free(tail);
    } while ((st = va_arg(ap, char *)));

    va_end(ap);
    return buff;
}

char *strappv(char **str) {
    if (!str || !str[0])
        return NULL;
    int *tmp = alloca(sizeof(int));
    *tmp = strlen(str[0]);
    int l = *tmp + 1;
    list_t *head = list_init(tmp, NULL), *tail = head;

    for (char **st = str + 1; *st; st++) {
        tmp = alloca(sizeof(int));
        *tmp = strlen(*st);
        tail->next = list_init(tmp, NULL);
        tail = tail->next;
        l += *tmp;
    }

    char *buff = malloc(sizeof(char) * l);
    l = 0;
    for (char **st = str; *st; st++) {
        strcpy(buff + l, *st);
        l += *(int *)head->val;
        tail = head;
        head = head->next;
        free(tail);
    }
    return buff;
}

void print_bytes(const unsigned char *buffer, size_t len) {
    if (!buffer)
        return;

    for (size_t i = 0; i < len; i++) {
        printf("%02hhx ", buffer[i]);
        //        if ((i + 1) % 4 == 0) printf("\n");
    }
    printf("\n");
}

void bytes_from_neighbour(const neighbour_t *n, u_int8_t buffer[18]) {
    memcpy(buffer, n->addr->sin6_addr.s6_addr, 16);
    memcpy(buffer + 16, &n->addr->sin6_port, 2);
}

void cprint(int fd, char *str, ...) {
    if (fd < 0)
        return;
    if (logfd < 0 && fd == 0)
        return;

    char *B = "", *F = "";
    if (fd == 0) {
        fd = logfd;
        if (fd == STDOUT_FILENO || fd == STDERR_FILENO) {
            B = LOGFD_B;
            F = LOGFD_F;
        }
    } else if (fd == STDOUT_FILENO) {
        B = STDOUT_B;
        F = STDOUT_F;
    } else if (fd == STDERR_FILENO) {
        B = STDERR_B;
        F = STDERR_F;
    }

    va_list ap;
    va_start(ap, str);

    unsigned int help;
    size_t len = 0;
    char *strbis = str, *strter;
    while (*strbis) {
        strter = strchrnul(strbis, '%');
        len += strter - strbis;
        if (*strter == '\0')
            break;
        strter++;
        assert(strter[0] != '\0');
        switch (strter[0]) {
        case 's':
            len += strlen(va_arg(ap, char *));
            break;
        case 'd':
            len += snprintf(NULL, 0, "%d", va_arg(ap, int));
            break;
        case 'u':
            len += snprintf(NULL, 0, "%u", va_arg(ap, unsigned int));
            break;
        case 'l':
            strter++;
            assert(strter[0] != '\0');
            switch (strter[0]) {
            case 'x':
                len += snprintf(NULL, 0, "%lx", va_arg(ap, long));
                break;
            case 'u':
                len += snprintf(NULL, 0, "%lu", va_arg(ap, unsigned long));
                break;
            case 'd':
                len += snprintf(NULL, 0, "%ld", va_arg(ap, long));
                break;
            default:
                assert(0);
            }
            break;
        case '*':
            strter++;
            assert(strter[0] == 's' || strter[0] == 'd');
            help = va_arg(ap, unsigned int);
            if (strter[0] == 's') {
                len += help;
                va_arg(ap, char *);
            } else
                len += max(help, snprintf(NULL, 0, "%d", va_arg(ap, int)));
            break;
        case '%':
            len += 1;
            break;
        default:
            assert(0);
        }
        strter++;
        strbis = strter;
    }
    va_end(ap);

    char *buffer = alloca(len + 1), *bufbis = buffer;
    buffer[len] = '\0';
    strbis = str;

    va_start(ap, str);
    while (*strbis) {
        strter = strchrnul(strbis, '%');
        strncpy(bufbis, strbis, strter - strbis);
        if (*strter == 0)
            break;
        bufbis += strter - strbis;
        strter++;
        switch (strter[0]) {
        case 's':
            bufbis += sprintf(bufbis, "%s", va_arg(ap, char *));
            break;
        case 'd':
            bufbis += sprintf(bufbis, "%d", va_arg(ap, int));
            break;
        case 'u':
            bufbis += sprintf(bufbis, "%u", va_arg(ap, unsigned int));
            break;
        case 'l':
            strter++;
            switch (strter[0]) {
            case 'x':
                bufbis += sprintf(bufbis, "%lx", va_arg(ap, long));
                break;
            case 'u':
                bufbis += sprintf(bufbis, "%lu", va_arg(ap, unsigned long));
                break;
            case 'd':
                bufbis += sprintf(bufbis, "%ld", va_arg(ap, long));
                break;
            }
            break;
        case '*':
            strter++;
            unsigned int tmp = va_arg(ap, unsigned int);
            if (strter[0] == 's') {
                memcpy(bufbis, va_arg(ap, char *), tmp);
                bufbis += tmp;
            } else {
                int num = va_arg(ap, int);
                unsigned int size = snprintf(NULL, 0, "%d", num);
                if (size < tmp) {
                    memset(bufbis, '0', tmp - size);
                    bufbis += tmp - size;
                }
                bufbis += sprintf(bufbis, "%d", num);
            }
            break;
        case '%':
            bufbis[0] = '%';
            bufbis++;
            break;
        }
        strter++;
        strbis = strter;
    }
    va_end(ap);

#define PRINT_STRING(S) write(fd, S, strlen(S))

    pthread_mutex_lock(&write_mutex);

    PRINT_STRING(CLBEG);

    PRINT_STRING(B);
    PRINT_STRING(F);

    write(fd, buffer, len);
    PRINT_STRING(RESET);

    write(fd, rl_line_buffer, rl_end);

    fsync(fd);
    pthread_mutex_unlock(&write_mutex);
}

void perrorbis(int err, const char *str) {
    if (str && *str)
        cprint(STDERR_FILENO, "%s: %s\n", str, strerror(err));
    else
        cprint(STDERR_FILENO, "%s\n", strerror(err));
}

void cperror(const char *str) { perrorbis(errno, str); }

int min(int a, int b) { return a < b ? a : b; }

int max(int a, int b) { return a < b ? b : a; }

char *purify(char *buffer, size_t *len) {
    size_t i = 0;
    while (i < *len && strchr(forbiden, buffer[i]) != NULL)
        i++;

    if (i == *len)
        return 0;

    while (strchr(forbiden, buffer[*len - 1]) != NULL)
        --*len;

    *len -= i;
    return buffer + i;
}

int is_number(char *str) {
    if (!str || !*str)
        return 0;
    while (*str && isdigit(*str))
        str++;
    return *str == 0;
}

// shamefully copied from
// https://stackoverflow.com/questions/1031645/how-to-detect-utf-8-in-plain-c
// slightly changed for non null-terminated strings
short is_utf8(const unsigned char *string, size_t len) {
    if (!string || len <= 0)
        return 0;

    size_t offset = 0;
    while (offset < len) {
        if (( // ASCII
              // use string[offset] <= 0x7F to allow ASCII control characters
                string[offset] == 0x09 || string[offset] == 0x0A ||
                string[offset] == 0x0D ||
                (0x20 <= string[offset] && string[offset] <= 0x7E))) {
            offset += 1;
            continue;
        }

        if (len - offset > 1 &&
            ( // non-overlong 2-byte
                (0xC2 <= string[offset] && string[offset] <= 0xDF) &&
                (0x80 <= string[offset + 1] && string[offset + 1] <= 0xBF))) {
            offset += 2;
            continue;
        }

        if (len - offset > 2 &&
            (( // excluding overlongs
                 string[offset] == 0xE0 &&
                 (0xA0 <= string[offset + 1] && string[offset + 1] <= 0xBF) &&
                 (0x80 <= string[offset + 2] && string[offset + 2] <= 0xBF)) ||
             ( // straight 3-byte
                 ((0xE1 <= string[offset] && string[offset] <= 0xEC) ||
                  string[offset] == 0xEE || string[offset] == 0xEF) &&
                 (0x80 <= string[offset + 1] && string[offset + 1] <= 0xBF) &&
                 (0x80 <= string[offset + 2] && string[offset + 2] <= 0xBF)) ||
             ( // excluding surrogates
                 string[offset] == 0xED &&
                 (0x80 <= string[offset + 1] && string[offset + 1] <= 0x9F) &&
                 (0x80 <= string[offset + 2] && string[offset + 2] <= 0xBF)))) {
            offset += 3;
            continue;
        }

        if (len - offset > 3 &&
            (( // planes 1-3
                 string[offset] == 0xF0 &&
                 (0x90 <= string[offset + 1] && string[offset + 1] <= 0xBF) &&
                 (0x80 <= string[offset + 2] && string[offset + 2] <= 0xBF) &&
                 (0x80 <= string[offset + 3] && string[offset + 3] <= 0xBF)) ||
             ( // planes 4-15
                 (0xF1 <= string[offset] && string[offset] <= 0xF3) &&
                 (0x80 <= string[offset + 1] && string[offset + 1] <= 0xBF) &&
                 (0x80 <= string[offset + 2] && string[offset + 2] <= 0xBF) &&
                 (0x80 <= string[offset + 3] && string[offset + 3] <= 0xBF)) ||
             ( // plane 16
                 string[offset] == 0xF4 &&
                 (0x80 <= string[offset + 1] && string[offset + 1] <= 0x8F) &&
                 (0x80 <= string[offset + 2] && string[offset + 2] <= 0xBF) &&
                 (0x80 <= string[offset + 3] && string[offset + 3] <= 0xBF)))) {
            offset += 4;
            continue;
        }

        return 0;
    }

    return 1;
}
