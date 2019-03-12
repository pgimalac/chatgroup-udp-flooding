#include <stdio.h>

#include "types.h"
#include "utils.h"
#include "network.h"

int
init() {
    int rc;
    rc = init_random();
    if (rc < 0) {
        perror("init:");
        return 1;
    }

    return init_network();
}

int main(void) {
    int rc;

    rc = init();
    if (rc != 0) return rc;
}
