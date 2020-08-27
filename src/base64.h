#ifndef __H_BASE64
#define __H_BASE64

#include <stdlib.h>

unsigned char *base64_encode(const unsigned char *src, size_t len,
                             size_t *out_len);

unsigned char *base64_decode(const unsigned char *src, size_t len,
                             size_t *out_len);

#endif
