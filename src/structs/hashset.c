#include "hashset.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "utils.h"

#define HASHSET_INITIAL_CAPACITY 16
#define HASHSET_RATIO_UPPER_LIMIT 0.8
#define HASHSET_RATIO_LOWER_LIMIT 0.1

#define GET_IP(n) ((neighbour_t*)n)->addr->sin6_addr.s6_addr
#define GET_PORT(n) ((neighbour_t*)n)->addr->sin6_port

hashset_t* hashset_init(){
    hashset_t *h = malloc(sizeof(hashset_t));
    if (h){
        h->size = 0;
        h->capacity = HASHSET_INITIAL_CAPACITY;
        h->tab = calloc(h->capacity, sizeof(list_t*));
        if (!h->tab){
            free(h);
            h = NULL;
        }
    }
    return h;
}

static short resize(hashset_t *h, int capacity){
    list_t** t = calloc(capacity, sizeof(list_t*));
    if (!t) return 0;

    for (int i = 0; i < h->capacity; list_destroy(h->tab[i], 0), i++)
        for (list_t* l = h->tab[i]; l != NULL; l = l->next)
            list_add(&t[hash_neighbour(GET_IP(l->val), GET_PORT(l->val)) % capacity], l->val);

    free(h->tab);
    h->capacity = capacity;
    h->tab = t;

    return 1;
}

short hashset_contains(hashset_t *h, u_int8_t ip[16], u_int16_t port){
    if (h == NULL || ip == NULL) return 0;

    for (list_t* l = h->tab[hash_neighbour(ip, port) % h->capacity]; l != NULL; l = l->next)
        if (memcmp(GET_IP(l->val), ip, 16) == 0 && port == GET_PORT(l->val))
            return 1;

    return 0;
}

short hashset_add(hashset_t *h, neighbour_t* n){
    if (h == NULL || n == NULL) return 0;

    u_int8_t *ip = n->addr->sin6_addr.s6_addr;
    u_int16_t port = n->addr->sin6_port;
    if(!hashset_contains(h, ip, port)){
        if (h->size + 1 > HASHSET_RATIO_UPPER_LIMIT * h->capacity)
            resize(h, h->capacity * 2);
        list_add(&h->tab[hash_neighbour(ip, port) % h->capacity], n);
        h->size ++;
        return 1;
    }

    return 0;
}

static short hashset_list_remove(list_t** l, u_int8_t ip[16], u_int16_t port){
    if (l != NULL){
        if (memcmp(GET_IP((*l)->val), ip, 16) == 0 && GET_PORT((*l)->val) == port){
            list_remove(l, 0);
            return 1;
        }

        list_t* tmp;
        for(tmp = *l;
            tmp->next != NULL
                && (memcmp(GET_IP(tmp->next->val), ip, 16)
                    || GET_PORT(tmp->next->val) != port);
            tmp = tmp->next) ;

        list_remove(&tmp->next, 0);
    }
    return 1;
}

short hashset_remove(hashset_t *h, u_int8_t ip[16], u_int16_t port){
    if (h != NULL && hashset_contains(h, ip, port)){
        int i = hash_neighbour(ip, port) % h->capacity;
        hashset_list_remove(&h->tab[i], ip, port);
        h->size--;
        if (h->size < HASHSET_RATIO_LOWER_LIMIT * h->capacity &&
            h->size > HASHSET_INITIAL_CAPACITY)
            resize(h, h->capacity / 2);
        return 1;
    }
    return 0;
}



void hashset_destroy(hashset_t *h){
    if (h == 0) return;

    for (int i = 0; i < h->capacity; i++)
        list_destroy(h->tab[i], 1);
    free(h->tab);
    free(h);
}
