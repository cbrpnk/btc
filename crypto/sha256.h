#ifndef SHA256_H
#define SHA256_H

#define SHA256_BLOCK_SIZE 64    // 512 bit

typedef uint8_t sha256_block[SHA256_BLOCK_SIZE];

int sha256_hash(uint8_t *out, const uint8_t *input, const uint64_t len);

#endif
