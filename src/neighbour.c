#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "network.h"
#include "tlv.h"
#include "flooding.h"
#include "utils.h"
#include "structs/list.h"
#include "interface.h"
#include "utils.h"

/**
 *
 * Neighbour initialisation function
 *
 */

neighbour_t *new_neighbour(const unsigned char ip[sizeof(struct in6_addr)],
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

    time_t now = time(0);

    memset(n, 0, sizeof(neighbour_t));
    n->pmtu = DEF_PMTU;
    n->pmtu_discovery_max = DEF_PMTU << 1;
    n->short_hello_count = 0;
    n->addr = addr;
    n->last_neighbour_send = now;
    n->last_pmtu_discovery = now;
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

        inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, INET6_ADDRSTRLEN);
        cprint(0, "Add %s, %d to potential neighbours\n", ipstr, ntohs(addr->sin6_port));
    }

    freeaddrinfo(r);

    return 0;
}

int send_neighbour_to(neighbour_t *p) {
    size_t i;
    int rc;
    list_t *l;
    neighbour_t *a;
    body_t *body;
    char ipstr[INET6_ADDRSTRLEN];

    for (i = 0; i < neighbours->capacity; i++) {
        for (l = neighbours->tab[i]; l; l = l->next) {
            a = (neighbour_t*)l->val;
            body = create_body();
            if (!body){
                cperror("malloc");
                continue;
            }

            rc = tlv_neighbour(&body->content,
                                      &a->addr->sin6_addr,
                                      a->addr->sin6_port);
            if (rc < 0){
                free(body);
                cperror("malloc");
                continue;
            }
            body->size = rc;

            rc = push_tlv(body, p);
            if (rc < 0) {
                cprint(STDERR_FILENO, "%s:%d Could not insert data into message queue\n", __FILE__, __LINE__);
                free(body->content);
                free(body);
            }
        }
    }

    inet_ntop(AF_INET6, &p->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN);
    cprint(0, "Send neighbours to (%s, %u).\n", ipstr, ntohs(p->addr->sin6_port));

    return 0;
}

void neighbour_flooding(short force) {
    size_t i;
    time_t now = time(0);

    list_t *l;
    neighbour_t *p;

    pthread_mutex_lock(&neighbours->mutex);

    for (i = 0; i < neighbours->capacity; i++) {
        for (l = neighbours->tab[i]; l; l = l->next) {
            p = (neighbour_t*)l->val;
            if (force || now - p->last_neighbour_send > NEIGHBOUR_TIMEOUT) {
                send_neighbour_to(p);
            }
        }
    }

    pthread_mutex_unlock(&neighbours->mutex);
}
