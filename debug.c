#include <stdio.h>
#include "debug.h"


// Debug function that prints an hex dump of a buffer
void dump_hex(void *buff, size_t size)
{
    for(size_t i=0; i<size; ++i) {
        printf("%02x ", ((unsigned char *) buff)[i]);
    }
    printf("\n");
}
