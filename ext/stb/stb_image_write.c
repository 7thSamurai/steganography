#include <stdlib.h>
#include "zlib/zlib.h"

static unsigned char *compress_for_stbiw(unsigned char *data, int data_len, int *out_len, int quality) {
    uLongf size = compressBound(data_len);
    unsigned char *buffer = (unsigned char*)malloc(size);

    if (!buffer)
        return NULL;

    if (compress2(buffer, &size, data, data_len, quality) != Z_OK) {
        free(buffer);
        return NULL;
    }

    *out_len = size;

    return buffer;
}

#define STBIW_ZLIB_COMPRESS compress_for_stbiw
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"
