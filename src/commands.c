#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <network.h>
#include <arpa/inet.h>

#include "types.h"
#include "commands.h"

static const char *usages[] = {
    "add <addr> <port>",
    "name <name>",
    "print",
    "quit"
};

static void add(char *buffer){
    int rc;
    char *name = 0, *service = 0;
    name = strtok(0, " ");
    service = strtok(0, " \n");
    if (!name || !service) {
        fprintf(stderr, "Usage: %s\n", usages[0]);
        return;
    }

    printf("Add %s, %s to potential neighbours\n", name, service);
    rc = add_neighbour(name, service, potential_neighbours);
    if (rc < 0) {
        perror("add neighbour");
    }
}

static void name(char *buffer){
    int len = strlen(buffer);
    if (len >= 30){
        printf("Nickname too long.\n");
    } else if (len < 3){
        printf("Nickname too short\n");
    } else {
        setnickname(buffer, len);
    }
}

static void __print(const neighbour_t *n){
    if (n != NULL && n->addr != NULL){
        char ipstr[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN) != NULL){
            printf("    @ %s / %d\n", ipstr, htons(n->addr->sin6_port));
            return;
        }
    }
    printf("    Could not display.\n");
}

static void print(char *buffer){
    if (hashset_isempty(neighbours)){
        printf("You have no neighbour\n");
    } else {
        printf("You have %d neighbour%s:\n", neighbours->size, neighbours->size == 1 ? "" : "s");
        hashset_iter(neighbours, __print);
    }
    if (hashset_isempty(potential_neighbours)){
        printf("You have no potential_neighbour.\n");
    } else {
        printf("You have %d potential neighbour%s:\n", potential_neighbours->size,
                    potential_neighbours->size == 1 ? "" : "s");
        hashset_iter(potential_neighbours, __print);
    }
    printf("\n");
}

static void quit(char *buffer){
    printf("Bye.\n");
    exit(0);
}

static void unknown(char *buffer){
    printf("Usage:\n");
    for (const char **usage = usages; *usage; usage++)
        printf("    %s\n", *usage);
}

static const char *names[] = {
    "add", "name", "print", "quit", NULL
};

static void (*commands[])(char*) = {
    add, name, print, quit, NULL
};


void handle_command(char *buffer) {
    char *ins = strtok(buffer, " \n");
    int ind;
    if (ins != NULL)
        for (ind = 0; names[ind] != NULL; ind ++)
            if (strcasecmp(ins, names[ind]) == 0){
                commands[ind](buffer);
                break;
            }

    if (ins == NULL || names[ind] == NULL)
        unknown(buffer);
}
