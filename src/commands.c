#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <network.h>

#include "commands.h"

static void add(char *buffer){
    int rc;
    char *name = 0, *service = 0;
    name = strtok(0, " ");
    service = strtok(0, " \n");
    if (!name || !service) {
        fprintf(stderr, "usage: add <addr> <port>\n");
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

static void quit(){
    printf("Bye.\n");
    exit(0);
}

void handle_command(char *buffer) {
    char *ins = strtok(buffer, " \n");
    if (strcasecmp(ins, "add") == 0)
        add(buffer);
    else if (strcasecmp(ins, "name") == 0)
        name(buffer);
    else if (strcasecmp(ins, "quit") == 0 || strcasecmp(ins, "exit") == 0)
        quit();
    else
        printf("Possible commands :\nadd <addr> <port>\nname <nickname>\nexit\nquit\n\n");
}
