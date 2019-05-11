#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <network.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>

#include "types.h"
#include "interface.h"
#include "flooding.h"
#include "websocket.h"

char pseudo[PSEUDO_LENGTH + 1];

const int pseudo_length = 28;
const char *pseudos[28] = {
                "Raskolnikov",
                "Mlle Swann",
                "Joshep K.",
                "Humbert Humbert",
                "Jacopo Belbo",
                "Méphistophélès",
                "Hamlet",
                "Alcèste",
                "Cthulhu",
                "Samsaget Gamgie",
                "Thomas Anderson",
                "Walter White",
                "Wednesday",
                "Morty",
                "Dexter",
                "The eleventh Doctor",
                "Elliot Alderson",
                "Doctor House",
                "Ragnar Lodbrok",
                "Hannibal",
                "Sherlock",
                "King Lear",
                "Zarathustra",
                "Deep Thought",
                "Arthur Dent",
                "Tyler Durden",
                "John Wayne",
                "HAL"
};

const char *ext[] = { 0, 0, "gif", "jpg", "png", "svg" };

// =========== COMMANDS part ===========

static const char *usages[] = {
    "add <addr> <port>",
    "name <name>",
    "random",
    "print",
    "juliusz",
    "neighbour",
    "clear",
    "chid",
    "transfert <type> <path to file>",
    "switchlog",
    "help",
    "quit",
    NULL,
};

static void add(const char *buf, size_t len) {
    if (buf == NULL || len == 0) {
        cprint(STDERR_FILENO, "Usage: %s\n", usages[0]);
        return;
    }

    int rc;
    char *buffer = alloca(len + 1);
    memcpy(buffer, buf, len);
    buffer[len] = 0;

    char *name = strtok(buffer, " "), *service = strtok(0, " \n");

    if (!name || !service) {
        cprint(STDERR_FILENO, "Usage: %s\n", usages[0]);
        return;
    }

    rc = add_neighbour(name, service);
    if (rc != 0)
        cprint(STDERR_FILENO, "Could not add the given neighbour: %s\n", gai_strerror(rc));
    else
        cprint(STDOUT_FILENO, "The neighbour %s, %s was added to potential neighbours\n", name, service);
}

static void name(const char *buffer, size_t len){
    if (buffer == NULL || len == 0)
        cprint(STDERR_FILENO, "Usage: %s\n", usages[1]);
    else
        setPseudo(buffer, len);
}

static void nameRandom(const char *buffer, size_t len){
    setRandomPseudo();
}

static void __print(const neighbour_t *n){
    char ipstr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &n->addr->sin6_addr, ipstr, INET6_ADDRSTRLEN);
    cprint(STDOUT_FILENO, "    @ %s / %d\n", ipstr, ntohs(n->addr->sin6_port));
}

static void print(const char *buffer, size_t len){
    if (hashset_isempty(neighbours)){
        cprint(STDOUT_FILENO, "You have no neighbour\n");
    } else {
        cprint(STDOUT_FILENO, "You have %lu neighbour%s:\n", neighbours->size,
            neighbours->size == 1 ? "" : "s");
        hashset_iter(neighbours, __print);
    }
    if (hashset_isempty(potential_neighbours)){
        cprint(STDOUT_FILENO, "You have no potential_neighbour.\n");
    } else {
        cprint(STDOUT_FILENO, "You have %lu potential neighbour%s:\n", potential_neighbours->size,
                    potential_neighbours->size == 1 ? "" : "s");
        hashset_iter(potential_neighbours, __print);
    }
}

static void juliusz(const char *buffer, size_t buflen){
    char j[] = "jch.irif.fr 1212";
    // on appelle strtok sur la chaine dans add
    // donc on doit pouvoir modifier la chaine,
    // d'où le tableau et pas un pointeur
    add(j, sizeof(j));
}

static void neighbour(const char *buffer, size_t buflen){
    neighbour_flooding(1);
}

static void clear(const char *buffer, size_t buflen){
    cprint(STDOUT_FILENO, EFFACER);
}

static void chid(const char *buffer, size_t buflen) {
    id = random_uint64();
    cprint(STDOUT_FILENO, "New id: %lx.\n", id);
}

#define MAX_BUF_SIZE ((1 << 16) - 1)
static void transfert(const char *path, size_t buflen) {
    int fd, rc;
    if (!path || buflen == 0){
        cprint(STDERR_FILENO, "Usage: %s\n", usages[8]);
        return;
    }

    uint8_t type = path[0] - '0';
    char buffer[MAX_BUF_SIZE], *npath = alloca(buflen);
    npath[buflen - 1] = 0;
    npath[buflen - 2] = 0;

    memcpy(npath, path + 2, buflen - 2);

    cprint(STDOUT_FILENO, "Send file %s on network.\n", npath);
    fd = open(npath, O_RDONLY);
    int err = errno;

    if (fd < 0) {
        perrorbis(err, "open");
        return;
    }

    rc = read(fd, buffer, MAX_BUF_SIZE);
    err = errno;
    close(fd);
    if (rc < 0) {
        perrorbis(err, "read");
        return;
    }


    cprint(0, "Transfering file %u.\n", rc);
    send_data(type, buffer, rc);
}

static void switchlog(const char *buffer, size_t len){
    char *bufferbis = NULL;
    if (buffer)
       bufferbis = purify((char*)buffer, &len);

    if (bufferbis == NULL){
        if (logfd == -1){
            logfd = STDERR_FILENO;
            cprint(STDOUT_FILENO, "Log are now writen on STDERR.\n");
        } else {
            if (logfd != STDERR_FILENO)
                close(logfd);
            logfd = -1;
            cprint(STDOUT_FILENO, "Log are not written anymore.\n");
        }
    } else {
        char *buf = alloca(len + 1);
        memcpy(buf, bufferbis, len);
        buf[len] = '\0';
        logfd = open(buf, O_WRONLY | O_CREAT | O_EXCL, S_IRWXO | S_IRWXG | S_IRWXU);
        if (logfd == -1){
            cperror("open");
            cprint(STDOUT_FILENO, "Log are now writen on STDERR.\n");
            logfd = STDERR_FILENO;
        } else
            cprint(STDOUT_FILENO, "Log are now writen on %*s.\n", len, buf);
    }

}

static void help(const char *buffer, size_t len){
    cprint(STDOUT_FILENO, "Possible commands are:\n");
    for (const char **usage = usages; *usage; usage++)
        cprint(STDOUT_FILENO, "    %s\n", *usage);
}

static void quit(const char *buffer, size_t len) {
    int *ret = malloc(sizeof(int));
    *ret = 0;
    pthread_exit(ret);
}

static void unknown(const char *buffer, size_t len){
    cprint(STDERR_FILENO, "Invalid command, possible commands are:\n");
    for (const char **usage = usages; *usage; usage++)
        cprint(STDERR_FILENO, "    %s\n", *usage);
}

static const char *names[] =
    {
     "add",
     "name",
     "random",
     "print",
     "juliusz",
     "neighbour",
     "clear",
     "chid",
     "transfert",
     "switchlog",
     "help",
     "quit",
     NULL
    };

static void (*interface[])(const char*, size_t) =
    {
     add,
     name,
     nameRandom,
     print,
     juliusz,
     neighbour,
     clear,
     chid,
     transfert,
     switchlog,
     help,
     quit,
     NULL
    };


void handle_command(const char *buffer, size_t len) {
    if (len == 0)
        return;
    cprint(STDOUT_FILENO, SEPARATOR);

    char *ins = memmem(buffer, len, " ", 1);
    if (!ins) ins = (char*)buffer + len;
    int ind;

    for (ind = 0; names[ind] != NULL; ind ++)
        if (strlen(names[ind]) == (size_t)(ins - buffer)
            && strncasecmp(buffer, names[ind], ins - buffer) == 0){
            if (len <= 1 + (size_t)(ins - buffer))
                interface[ind](NULL, 0);
            else
                interface[ind](ins + 1, len - (ins - buffer) - 1);
            break;
        }

    if (names[ind] == NULL)
        unknown(buffer, len);
    cprint(STDOUT_FILENO, SEPARATOR);
}

// =========== PSEUDO part ===========

const char* getPseudo(){
    return pseudo;
}

void setPseudo(const char *buf, size_t len){
    buf = purify((char*)buf, &len);

    if (len > PSEUDO_LENGTH){
        cprint(STDERR_FILENO, "Nickname too long.\n");
    } else if (len < 3){
        cprint(STDERR_FILENO, "Nickname too short\n");
    } else {
        for (size_t i = 0; i < len; i++)
            if (strchr(forbiden, buf[i]) == NULL)
                pseudo[i] = buf[i];
            else
                pseudo[i] = ' ';

        pseudo[len] = '\0';
        cprint(STDOUT_FILENO, "Nickname set to \"%s\"\n", pseudo);
    }
}

void setRandomPseudo(){
    int index = rand() % pseudo_length;
    strcpy(pseudo, pseudos[index]);
    cprint(STDOUT_FILENO, "Nickname set to \"%s\"\n", pseudo);
}

// OTHER

void print_message(const u_int8_t* buffer, int size){
    time_t now = time(0);
    struct tm *t = localtime(&now);
    if (is_utf8(buffer, size))
        cprint(STDOUT_FILENO, "%*d:%*d:%*d > %*s\n", 2,
               t->tm_hour, 2, t->tm_min, 2, t->tm_sec, size, buffer);
    else
        cprint(STDOUT_FILENO, "%*d:%*d:%*d > (MALFORMED UTF8)\n", 2,
               t->tm_hour, 2, t->tm_min, 2, t->tm_sec);
}

void handle_input(char *buffer, size_t buflen) {
    char *purified = purify(buffer, &buflen);
    if (!purified) return;
    if (purified[0] == COMMAND)
        handle_command(purified + 1, buflen - 1);
    else {
        send_data(0, purified, buflen);
        print_web((uint8_t*)purified, buflen);
    }
}

void print_file(uint8_t type, const u_int8_t *buffer, size_t len) {
    int fd;
    char name[256], fp[1024];
    char img[2048];
    switch (type) {
    case 0:
        print_message((u_int8_t*)buffer, len);
        print_web((u_int8_t*)buffer, len);
        break;

    case 2:
    case 3:
    case 4:
        sprintf(name, "%lx.%s", random_uint64(), ext[(int)type]);
        sprintf(fp, "/tmp/%s/%s", tmpdir, name);
        fd = open(fp, O_CREAT|O_WRONLY, 0722);
        if (fd < 0) {
            cperror("open");
            return;
        }

        write(fd, buffer, len);
        close(fd);

        cprint(STDOUT_FILENO, "New file received %s.\n", fp);
        fd = sprintf(img, "<img src='/%s'/>", name);
        print_web((u_int8_t*)img, fd);
        break;

    default:
        cprint(0, "Dont know what to do with file type %d.\n", type);
        break;
    }
}
