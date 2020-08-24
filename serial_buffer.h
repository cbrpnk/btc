#ifndef SERIAL_BUFFER_H
#define SERIAL_BUFFER_H

#include <stdint.h>

// Buffer serialization
typedef struct serial_buffer {
    uint8_t *data;
    // Index of the next byte to write
    unsigned int next;
    size_t size;
    size_t capacity;
} serial_buffer;

void serial_buffer_init(serial_buffer *buf, size_t size);
void serial_buffer_destroy(serial_buffer *buf);
void serial_buffer_require(serial_buffer *buf, size_t size);

void serial_buffer_push_u8(serial_buffer *buf, uint8_t val);
void serial_buffer_push_u16(serial_buffer *buf, uint16_t val);
void serial_buffer_push_u32(serial_buffer *buf, uint32_t val);
void serial_buffer_push_u64(serial_buffer *buf, uint64_t val);
void serial_buffer_push_mem(serial_buffer *buf, char *val, size_t len);

uint8_t  serial_buffer_pop_u8(serial_buffer *buf);
uint16_t serial_buffer_pop_u16(serial_buffer *buf);
uint32_t serial_buffer_pop_u32(serial_buffer *buf);
uint64_t serial_buffer_pop_u64(serial_buffer *buf);
void     serial_buffer_pop_mem(void *val, size_t len, serial_buffer *buf);


#endif
