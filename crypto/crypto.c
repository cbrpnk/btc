#include <math.h>
#include <time.h>
#include <stdlib.h>

#include "crypto.h"
#include "sha256.h"

uint64_t gen_nonce_64()
{
    srand(time(NULL));
    // Concatenate 2 32bit rand(), assumes rand() returns a 32 bit number
    return ((uint64_t) rand()) | (((uint64_t) rand()) << 32);
}

uint64_t gen_nonce_16()
{
    srand(time(NULL));
    return (uint16_t) rand();
}

uint32_t gen_checksum(unsigned char *buf, size_t len)
{
    // The first 4 byte of a double sha256
    uint32_t checksum[8];
    sha256_hash((uint8_t *) checksum, buf, len);
    sha256_hash((uint8_t *) checksum, (uint8_t *) checksum, 32);
    
    return *((uint32_t *)checksum);
}

