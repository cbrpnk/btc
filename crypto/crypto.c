#include <math.h>
#include <time.h>
#include <stdlib.h>
#include <openssl/sha.h>

#include "crypto.h"

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
    unsigned char checksum[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buf, len);
    SHA256_Final(checksum, &ctx);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, checksum, SHA256_DIGEST_LENGTH);
    SHA256_Final(checksum, &ctx);
    return *((uint32_t *) checksum);
}

