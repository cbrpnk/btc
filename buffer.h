#ifndef BITCOIN_BUFFER_H
#define BITCOIN_BUFFER_H

#include <stdint.h>

// Buffer serialization
typedef struct buffer {
    unsigned char *data;
    // Index of the next byte to write
    unsigned int next;
    size_t size;
    size_t capacity;
} buffer;

void buffer_init(buffer *buf);
void buffer_destroy(buffer *buf);
void buffer_require(buffer *buf, size_t size);
void buffer_push_u8(buffer *buf, unsigned char val);
void buffer_push_u16(buffer *buf, uint16_t val);
void buffer_push_u32(buffer *buf, uint32_t val);
void buffer_push_u64(buffer *buf, uint64_t val);

#endif
