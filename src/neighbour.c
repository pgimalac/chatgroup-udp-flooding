#include <stdio.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "network.h"
#include "tlv.h"
#include "flooding.h"
#include "utils.h"
#include "structs/list.h"
#include "interface.h"
#include "utils.h"

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
