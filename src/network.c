#define _GNU_SOURCE

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

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
        hashset_destroy(neighbours);
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
    if (!iov)
        return 0;
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

    u_int16_t body_length;
    memcpy(&body_length, buffer + 2, sizeof(body_length));
    body_length = ntohs(body_length);

    if (body_length + 4 > buflen){
        cprint(STDERR_FILENO, "body_length %d, buflen %d\n", body_length, buflen);
        return BUFINC;
    }
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

int bytes_to_message(const u_int8_t *src, size_t buflen, neighbour_t *n, message_t *msg) {
    if (msg == NULL) return -8;
    int rc = check_message_size(src, buflen);
    if (rc < 0) return rc;

    u_int16_t size;
    memcpy(&size, src + 2, sizeof(size));
    size = ntohs(size);

    if (size == 0)
        return -9;

    msg->magic = src[0];
    msg->version = src[1];
    msg->body_length = size;
    msg->body = 0;
    msg->dst = n;

    size_t i = 4;
    body_t *body, *bptr;

    while (i < buflen) {
        body = malloc(sizeof(body_t));
        if (!body){
            cperror("malloc");
            break;
        }

        memset(body, 0, sizeof(body_t));

        if (src[i] == BODY_PAD1) body->size = 1;
        else body->size = 2 + src[i + 1];

        body->content = voidndup(src + i, body->size);

        if (!body->content){
            cperror("malloc");
            free(body);
            body = 0;
            break;
        }

        i += body->size;

        if (!msg->body) msg->body = body;
        else bptr->next = body;
        bptr = body;
    }

    if (i < buflen){ // loop exit with break
        for (body = msg->body; body; body = bptr){
            bptr = body->next;
            free(body->content);
            free(body);
        }
        return -10;
    }

    return 0;
}

int start_server(int port) {
    int rc, s;
    memset(&local_addr, 0, sizeof(local_addr));

    s = socket(PF_INET6, SOCK_DGRAM, 0);
    if (s < 0 ) {
        cperror("socket");
        return -1;
    }

    rc = fcntl(s, F_GETFL);
    if (rc < 0) {
        cperror("fnctl");
        return -1;
    }

    rc = fcntl(s, F_SETFL, rc | O_NONBLOCK);
    if (rc < 0) {
        cperror("fnctl");
        return -1;
    }

    local_addr.sin6_family = AF_INET6;
    local_addr.sin6_port = htons(port);
    rc = bind(s, (struct sockaddr*)&local_addr, sizeof(local_addr));
    if (rc < 0) {
        cperror("bind");
        return -2;
    }

    char out[INET6_ADDRSTRLEN];
    assert (inet_ntop(AF_INET6, &local_addr, out, INET6_ADDRSTRLEN) != NULL);
    if (local_addr.sin6_port)
        cprint(0, "Start server at %s on port %d.\n", out, ntohs(local_addr.sin6_port));
    else
        cprint(0, "Start server at %s on a random port.\n", out);

    int one = 1;
    rc = setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
    if (rc < 0) {
        cperror("setsockopt");
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
    if (addr == NULL){
        cperror("malloc");
        return 0;
    }
    memset(addr, 0, sizeof(struct sockaddr_in6));
    addr->sin6_family = AF_INET6;
    addr->sin6_port = port;
    memcpy(addr->sin6_addr.s6_addr, ip, sizeof(struct in6_addr));

    neighbour_t *n = malloc(sizeof(neighbour_t));
    if (n == NULL){
        cperror("malloc");
        free(addr);
        return 0;
    }

    memset(n, 0, sizeof(neighbour_t));
    n->pmtu = DEF_PMTU;
    n->short_hello_count = 0;
    n->addr = addr;
    n->last_neighbour_send = time(0);
    if (n->last_neighbour_send == -1){
        cperror("time");
        n->last_neighbour_send = 0;
    }
    n->status = NEIGHBOUR_POT;
    n->tutor_id = 0;

    if (tutor) {
        n->tutor_id = malloc(18);
        /* doesn't matter if tutor_id is null, at worst we don't send a warning */

        if (n->tutor_id)
            bytes_from_neighbour(tutor, n->tutor_id);
    }

    int rc = hashset_add(potential_neighbours, n);
    if (rc == 2){
        cprint(0, "Tried to add a neighbour to potentials but it was already in.\n");
        free(n->tutor_id);
        free(n->addr);
        free(n);
    } else if (rc == 0)
        perrorbis(ENOMEM, "hashset_add");
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
        cprint(0, "getaddrinfo: %s\n", gai_strerror(rc));
        perrorbis(rc, "getaddrinfo: %s\n");
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
        cprint(0, "Add %s, %d to potential neighbours\n", ipstr, ntohs(addr->sin6_port));
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
    cprint(0, "* Containing PAD1\n");
}

static void onsend_padn(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    cprint(0, "* Containing PadN %u\n", tlv[1]);
}

static void onsend_hello(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    dst->last_hello_send = time(0);
    if (tlv[1] == 8) {
        dst->short_hello_count++;
        cprint(0, "* Containing short hello.\n");
    } else {
        cprint(0, "* Containing long hello.\n");
    }
}

static void onsend_neighbour(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    cprint(0, "* Containing neighbour.\n");
    time_t tmp = time(0);
    if (tmp == -1)
        cperror("time");
    else
        dst->last_neighbour_send = tmp;
}

static void onsend_data(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    hashmap_t *map;
    data_info_t *dinfo;
    datime_t *datime;
    u_int8_t buffer[18];
    time_t now = time(0), delta;
    if (now == -1)
        cperror("time");

    cprint(0, "* Containing data.\n");

    map = hashmap_get(flooding_map, tlv + 2);
    if (!map){
        cprint(STDERR_FILENO, "%s:%d Tried to get an element from flooding_map but it wasn't in.\n",
            __FILE__, __LINE__);
        return;
    }

    bytes_from_neighbour(dst, buffer);
    dinfo = hashmap_get(map, buffer);
    ++dinfo->send_count;

    if (now != -1){
        dinfo->time = now + (rand() % (1 << dinfo->send_count)) + (1 << dinfo->send_count);
        delta = dinfo->time - now;
        datime = hashmap_get(data_map, tlv + 2);
        if (!datime)
            cprint(STDERR_FILENO, "%s:%d Tried to get a tlv from a data_map but it wasn't in.\n", __FILE__, __LINE__);
        else
            datime->last = now;

        if (delta < tv->tv_sec)
            tv->tv_sec = delta;
    }
}

static void onsend_ack(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    cprint(0, "* Containing ack.\n");
}

static void onsend_goaway(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    cprint(0, "* Containing go away %u.\n", tlv[2]);
}

static void onsend_warning(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    cprint(0, "* Containing warning.\n");
}

static void onsend_unknow(const u_int8_t *tlv, neighbour_t *dst, struct timeval *tv) {
    cprint(0, "* Containing an unknow tlv.\n");
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
    cprint(0, "> Send message to (%s, %u).\n", ipstr, ntohs(msg->dst->addr->sin6_port));

    for (p = msg->body; p; p = p->next) {
        if (p->content[0] >= 9) onsend_unknow(p->content, msg->dst, tv);
        else onsenders[(int)p->content[0]](p->content, msg->dst, tv);
    }

    cprint(0, "\n");

    hdr.msg_name = msg->dst->addr;
    hdr.msg_namelen = sizeof(struct sockaddr_in6);
    hdr.msg_iovlen = message_to_iovec(msg, &hdr.msg_iov);
    if (!hdr.msg_iov || hdr.msg_iovlen == 0)
        return errno;

    rc = sendmsg(sock, &hdr, MSG_NOSIGNAL);
    int err = errno;
    free(hdr.msg_iov);
    msg->body_length = htons(msg->body_length);
    if (rc < 0) return err;

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
    if (rc < 0) return errno;
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
        cprint(STDERR_FILENO, "IPV6_PKTINFO non trouvé\n");
        return -2;
    }

    char ipstr[INET6_ADDRSTRLEN];
    assert (inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
    cprint(0, "Receive message from (%s, %u).\n", ipstr, ntohs(addr->sin6_port));

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

    cprint(0, "Send go away leave to neighbours before quit.\n");

    rc = tlv_goaway(&goaway.content, GO_AWAY_LEAVE, "Bye !", 5);
    if (rc >= 0){
        goaway.size = rc;

        msg.magic = MAGIC;
        msg.version = VERSION;
        msg.body_length = goaway.size;
        msg.body = &goaway;

        for (i = 0; i < neighbours->capacity; i++) {
            for (l = neighbours->tab[i]; l; l = l->next) {
                msg.dst = (neighbour_t*)l->val;
                rc = send_message(sock, &msg, &tv);
                if (rc != 0) {
                    perrorbis(rc, "send_message");
                    assert (inet_ntop(AF_INET6, &msg.dst->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL);
                    cprint(STDERR_FILENO, "Failed to send goaway to (%s, %u).\n", ipstr, ntohs(msg.dst->addr->sin6_port));
                }
            }
        }

        free(goaway.content);
    }

    cprint(STDOUT_FILENO, "Bye.\n");
    exit(sig);
}
