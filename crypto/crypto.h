#ifndef BITCOIN_CRYPTO_H
#define BITCOIN_CRYPTO_H

#define BC_SHA256_LEN 32

uint64_t gen_nonce_64();
uint64_t gen_nonce_16();
uint32_t gen_checksum(unsigned char *buf, size_t len);

#endif
