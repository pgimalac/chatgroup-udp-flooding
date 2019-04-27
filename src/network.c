#define _GNU_SOURCE

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "network.h"
#include "tlv.h"
#include "interface.h"

// user address
struct sockaddr_in6 local_addr;

/**
 * Generic network functions
 *
 */

int init_network() {
    id = random_uint64();
    neighbours = hashset_init();
    if (neighbours == NULL){
        return -1;
    }
    potential_neighbours = hashset_init();
    if (potential_neighbours == NULL){
        free(neighbours);
        return -1;
    }
    return 0;
}

size_t message_to_iovec(message_t *msg, struct iovec **iov_dest) {
    body_t *p;
    ssize_t i;
    struct iovec *iov;

    int nb = 1;
    for (p = msg->body; p; p = p->next)
        nb++;

    iov = calloc(nb, sizeof(struct iovec));
    if (!iov) return 0;
    *iov_dest = iov;

    iov[0].iov_base = msg;
    iov[0].iov_len = 4;

    for (i = 1, p = msg->body; p; p = p->next, i++) {
        iov[i].iov_base = p->content;
        iov[i].iov_len = p->size;
    }

    return i;
}


static int check_message_size(const u_int8_t* buffer, int buflen){
    if (buffer == NULL)
        return BUFNULL;
    if (buflen < 4)
        return BUFSH;

    u_int16_t body_length = be16toh(*(u_int16_t*)(buffer + 2));
    if (body_length + 4 > buflen)
        return BUFINC;
    buflen = body_length + 4;

    int i = 4, body_num = 0, rc;
    while (i < buflen){
        i++;
        if (buffer[i - 1] != BODY_PAD1){
            if (i >= buflen)
                return TLVSH;
            i += 1 + (u_int8_t)buffer[i];
        }
        body_num ++;
    }

    if (i != buflen)
        return SUMLONG;

    i = 4;
    while (i < buflen){
        rc = check_tlv_size(buffer + i);
        if (rc < 0)
            return rc;
        i += rc;
    }

    return body_num;
}

message_t *bytes_to_message(const u_int8_t *src, size_t buflen, neighbour_t *n) {
    int rc = check_message_size(src, buflen);
    if (rc < 0) return 0;

    u_int16_t size;
    memcpy(&size, src + 2, sizeof(size));
    size = ntohs(size);

    if (size == 0)
        return 0;

    message_t *msg = create_message(src[0], src[1], size, 0, n);
    if (!msg)
        return 0;

    size_t i = 4;
    body_t *body, *bptr;

    while (i < buflen) {
        body = malloc(sizeof(body_t));
        if (!body){ // todo : better error handling
            perror("malloc");
            break;
        }

        memset(body, 0, sizeof(body_t));

        if (src[i] == BODY_PAD1) body->size = 1;
        else body->size = 2 + src[i + 1];

        body->content = voidndup(src + i, body->size);

        if (!body->content){ // todo : better error handling
            perror("malloc");
            free(body);
            body = 0;
            break;
        }

        i += body->size;

        // TODO: find something better
        if (!msg->body) msg->body = body;
        else bptr->next = body;
        bptr = body;
    }

    if (i < buflen){ // loop exit with break
        free_message(msg);
        return 0;
    }

    return msg;
}

int start_server(int port) {
    int rc, s;
    memset(&local_addr, 0, sizeof(struct sockaddr_in6));

    s = socket(PF_INET6, SOCK_DGRAM, 0);
    if (s < 0 ) {
        perror("socket");
        return -1;
    }

    local_addr.sin6_family = AF_INET6;
    local_addr.sin6_port = htons(port);
    rc = bind(s, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if (rc < 0) {
        perror("bind");
        return -2;
    }

    char out[INET6_ADDRSTRLEN];
    assert (inet_ntop(AF_INET6, &local_addr, out, INET6_ADDRSTRLEN) != NULL);
    if (local_addr.sin6_port)
        dprintf(logfd, "%s%sStart server at %s on port %d.\n%s", LOGFD_F, LOGFD_B, out, ntohs(local_addr.sin6_port), RESET);
    else
        dprintf(logfd, "%s%sStart server at %s on a random port.\n%s", LOGFD_F, LOGFD_B, out, RESET);

    int one = 1;
    rc = setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
    if (rc < 0) {
        perror("setsockopt");
        return -3;
    }

    return s;
}


/**
 *
 * Neighbour initialisation function
 *
 */

neighbour_t *
new_neighbour(const unsigned char ip[sizeof(struct in6_addr)],
              unsigned int port, const neighbour_t *tutor) {
    struct sockaddr_in6 *addr = malloc(sizeof(struct sockaddr_in6));
    if (addr == NULL) return 0;
    memset(addr, 0, sizeof(struct sockaddr_in6));
    addr->sin6_family = AF_INET6;
    addr->sin6_port = port;
    memmove(addr->sin6_addr.s6_addr, ip, sizeof(struct in6_addr));

    neighbour_t *n = malloc(sizeof(neighbour_t));
    if (n == NULL){
        free(addr);
        return 0;
    }

    memset(n, 0, sizeof(neighbour_t));
    n->pmtu = 500;
    n->short_hello_count = 0;
    n->addr = addr;
    n->last_neighbour_send = time(0);
    n->status = NEIGHBOUR_POT;
    n->tutor_id = 0;

    if (tutor) {
        n->tutor_id = malloc(18);
        if (!n->tutor_id) {
            perror("malloc");
            free(n);
            return 0;
        }

        bytes_from_neighbour(tutor, n->tutor_id);
    }

    hashset_add(potential_neighbours, n);
    return hashset_get(potential_neighbours, ip, port);
}

int add_neighbour(const char *hostname, const char *service) {
    int rc, s;
    char ipstr[INET6_ADDRSTRLEN] = { 0 };
    struct addrinfo hints = { 0 }, *r = NULL;
    struct sockaddr_in6 *addr;

    hints.ai_family = PF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_V4MAPPED | AI_ALL;

    rc = getaddrinfo (hostname, service, &hints, &r);
    if (rc != 0){
        return rc;
    }

    for (struct addrinfo *p = r; p != NULL; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0)
            continue;
        close(s);


        addr = (struct sockaddr_in6*)p->ai_addr;
        if (!new_neighbour(addr->sin6_addr.s6_addr, addr->sin6_port, 0))
            continue;

        assert (inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
        dprintf(logfd, "%s%sAdd %s, %d to potential neighbours\n%s", LOGFD_F, LOGFD_B, ipstr, ntohs(addr->sin6_port), RESET);
    }

    freeaddrinfo(r);

    return 0;
}

/**
 *
 * Sending message section
 *
 * Events on send and sending function
 *
 */

typedef void (*onsend_fnc)(const u_int8_t*, neighbour_t*, struct timeval *tv);

static void onsend_pad1(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    dprintf(logfd, "%s%s* Containing PAD1\n%s", LOGFD_F, LOGFD_B, RESET);
}

static void onsend_padn(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    dprintf(logfd, "%s%s* Containing PadN %u\n%s", LOGFD_F, LOGFD_B, tlv[1], RESET);
}

static void onsend_hello(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    dst->last_hello_send = time(0);
    if (tlv[1] == 8) {
        dst->short_hello_count++;
        dprintf(logfd, "%s%s* Containing short hello.\n%s", LOGFD_F, LOGFD_B, RESET);
    } else {
        dprintf(logfd, "%s%s* Containing long hello.\n%s", LOGFD_F, LOGFD_B, RESET);
    }
}

static void onsend_neighbour(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    dprintf(logfd, "%s%s* Containing neighbour.\n%s", LOGFD_F, LOGFD_B, RESET);
    dst->last_neighbour_send = time(0);
}

static void onsend_data(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    hashmap_t *map;
    data_info_t *dinfo;
    datime_t *datime;
    u_int8_t buffer[18];
    time_t now = time(0), delta;

    map = hashmap_get(flooding_map, tlv + 2);
    bytes_from_neighbour(dst, buffer);
    dinfo = hashmap_get(map, buffer);
    dinfo->time = now + (rand() % ((1 << (++dinfo->send_count + 1)))) + 1;
    delta = dinfo->time - now;

    datime = hashmap_get(data_map, tlv + 2);
    datime->last = now;

    if (delta < tv->tv_sec) {
        tv->tv_sec = delta;
    }

    dprintf(logfd, "%s%s* Containing data.\n%s", LOGFD_F, LOGFD_B, RESET);
}

static void onsend_ack(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    dprintf(logfd, "%s%s* Containing ack.\n%s", LOGFD_F, LOGFD_B, RESET);
}

static void onsend_goaway(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    dprintf(logfd, "%s%s* Containing go away %u.\n%s", LOGFD_F, LOGFD_B, tlv[2], RESET);
}

static void onsend_warning(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    dprintf(logfd, "%s%s* Containing warning.\n%s", LOGFD_F, LOGFD_B, RESET);
}

static void onsend_unknow(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    dprintf(logfd, "%s%s* Containing an unknow tlv.\n%s", LOGFD_F, LOGFD_B, RESET);
}

onsend_fnc onsenders[9] = {
               onsend_pad1,
               onsend_padn,
               onsend_hello,
               onsend_neighbour,
               onsend_data,
               onsend_ack,
               onsend_goaway,
               onsend_warning,
               onsend_unknow
};

int send_message(int sock, message_t *msg, struct timeval *tv) {
    int rc;
    struct msghdr hdr = { 0 };
    body_t *p;
    char ipstr[INET6_ADDRSTRLEN];

    msg->body_length = htons(msg->body_length);

    assert (inet_ntop(AF_INET6, &msg->dst->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
    dprintf(logfd, "%s%s> Send message to (%s, %u).\n%s", LOGFD_F, LOGFD_B, ipstr, ntohs(msg->dst->addr->sin6_port), RESET);

    for (p = msg->body; p; p = p->next) {
        if (p->content[0] >= 9) onsend_unknow(p->content, msg->dst, tv);
        else onsenders[(int)p->content[0]](p->content, msg->dst, tv);
    }

    dprintf(logfd, "%s%s\n%s", LOGFD_F, LOGFD_B, RESET);

    hdr.msg_name = msg->dst->addr;
    hdr.msg_namelen = sizeof(struct sockaddr_in6);
    hdr.msg_iovlen = message_to_iovec(msg, &hdr.msg_iov);
    if (!hdr.msg_iov) return -1;

    rc = sendmsg(sock, &hdr, MSG_NOSIGNAL);
    free(hdr.msg_iov);
    // free might change errno but prevents a memory leak
    // find a way to avoid using free here ?
    if (rc < 0) return -2;

    return 0;
}

int recv_message(int sock, struct sockaddr_in6 *addr, u_int8_t *out, size_t *buflen) {
    if (!out || !buflen) return 0;

    int rc;
    struct in6_pktinfo *info = 0;
    struct iovec iov[1];
    struct msghdr hdr = { 0 };
    struct cmsghdr *cmsg;
    union {
        unsigned char cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
        struct cmsghdr align;
    } u;

    iov[0].iov_base = out;
    iov[0].iov_len = *buflen;

    hdr.msg_name = addr;
    hdr.msg_namelen = sizeof(*addr);
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = (struct cmsghdr*)u.cmsgbuf;
    hdr.msg_controllen = sizeof(u.cmsgbuf);

    rc = recvmsg(sock, &hdr, 0);
    if (rc < 0) return -1;
    *buflen = rc;

    cmsg = CMSG_FIRSTHDR(&hdr);
    while(cmsg) {
        if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
            (cmsg->cmsg_type == IPV6_PKTINFO)) {
            info = (struct in6_pktinfo*)CMSG_DATA(cmsg);
            break;
        }
        cmsg = CMSG_NXTHDR(&hdr, cmsg);
    }

    if(info == NULL) {
        /* ce cas ne devrait pas arriver */
        fprintf(stderr, "%s%sIPV6_PKTINFO non trouvé\n%s", STDERR_F, STDERR_B, RESET);
        return -2;
    }

    char ipstr[INET6_ADDRSTRLEN];
    assert (inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
    dprintf(logfd, "%s%sReceive message from (%s, %u).\n%s", LOGFD_F, LOGFD_B, ipstr, ntohs(addr->sin6_port), RESET);

    return 0;
}

void quit_handler (int sig) {
    int rc;
    size_t i;
    list_t *l;
    char ipstr[INET6_ADDRSTRLEN];
    message_t msg = { 0 };
    body_t goaway = { 0 };
    struct timeval tv = { 0 };

    dprintf(logfd, "%s%sSend go away leave to neighbours before quit.\n%s", LOGFD_F, LOGFD_B, RESET);

    goaway.size = tlv_goaway(&goaway.content, GO_AWAY_LEAVE, "Bye !", 5);

    msg.magic = 93;
    msg.version = 2;
    msg.body_length = goaway.size;
    msg.body = &goaway;

    for (i = 0; i < neighbours->capacity; i++) {
        for (l = neighbours->tab[i]; l; l = l->next) {
            msg.dst = (neighbour_t*)l->val;
            rc = send_message(sock, &msg, &tv);
            if (rc < 0) {
                assert (inet_ntop(AF_INET6, &msg.dst->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
                fprintf(stderr, "%s%sFailed to send goaway to (%s, %u).\n%s", STDERR_F, STDERR_B, ipstr, ntohs(msg.dst->addr->sin6_port), RESET);
            }
        }
    }

    free(goaway.content);

    printf("%s%sBye.\n%s", LOGFD_F, LOGFD_B, RESET);
    exit(sig);
}
