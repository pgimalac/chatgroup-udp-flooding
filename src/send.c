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

static void frag_data(u_int8_t type, const char *buffer, u_int16_t size) {
    uint16_t i = 0, n = size / 233, count = 0, len;
    uint16_t nsize = htons(size), pos;
    body_t data = { 0 };
    char content[256], *offset;
    u_int32_t nonce_frag = random_uint32();

    cprint(0, "Fragment message of total size %u bytes.\n", size);

    for (i = 0; i <= n; i++) {
        offset = content;
        memset(offset, 0, 256);
        memcpy(offset, &nonce_frag, sizeof(nonce_frag));
        offset += sizeof(nonce_frag);

        *offset++ = type; // data type

        memcpy(offset, &nsize, 2); // size
        offset += 2;

        pos = htons(count);
        memcpy(offset, &pos, 2); // position
        offset += 2;

        len = size - count < 233 ? size - count : 233;
        memcpy(offset, buffer + count, len);
        offset += len;

        data.size = tlv_data(&data.content, id, random_uint32(), 220, content, len + 9);
        flooding_add_message(data.content, data.size, 1);
        free(data.content);
        count += len;
    }
}

void send_data(u_int8_t type, const char *buffer, u_int16_t size){
    if (buffer == 0 || size <= 0) return;

    if (size > 255) {
        frag_data(type, buffer, size);
        return;
    }

    body_t data = { 0 };
    int rc = tlv_data(&data.content, id, random_uint32(), type, buffer, size);

    if (rc < 0){
        if (rc == -1)
            cperror("tlv_data");
        else if (rc == -2)
            cprint(0, "Message too long but supposed to be cut...\n");
        return;
    }

    data.size = rc;

    if (flooding_add_message(data.content, data.size, 1) != 0)
        cperror("tlv_data");

    free(data.content);
}


