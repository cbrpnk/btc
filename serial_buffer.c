#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "serial_buffer.h"

void serial_buffer_init(serial_buffer *buf, size_t capacity)
{
    buf->capacity = capacity;
    buf->data = calloc(buf->capacity, 1);
    buf->next = 0;
    buf->size = 0;
}

void serial_buffer_init_from_data(serial_buffer *buf, void *data, size_t len)
{
    buf->capacity = len;
    buf->data = calloc(1, buf->capacity);
    printf("---->%d", buf->capacity);
    memcpy(buf->data, data, len);
    buf->next = 0;
    buf->size = len;
}

void serial_buffer_destroy(serial_buffer *buf)
{
    buf->capacity = 0;
    free(buf->data);
    buf->next = 0;
    buf->size = 0;
}

// Make sur there's at least size free bytes in the buffer
void serial_buffer_require(serial_buffer *buf, size_t size)
{ 
    if(((int)(buf->capacity - buf->next - size)) <= 0) {
        // Double buffer capacity
        size_t new_capacity = buf->capacity * 2;
        buf->data = realloc(buf->data, new_capacity);
        memset(buf->data+buf->capacity, 0, buf->capacity);
        buf->capacity = new_capacity;
    }
}

void serial_buffer_push_u8(serial_buffer *buf, uint8_t val)
{
    serial_buffer_require(buf, 1);
    buf->data[buf->next] = val;
    buf->next++;
    if(buf->next > buf->size) buf->size = buf->next;
}

void serial_buffer_push_u16(serial_buffer *buf, uint16_t val)
{
    serial_buffer_require(buf, sizeof(uint16_t));
    memcpy((uint16_t *) (buf->data + buf->next), &val, sizeof(uint16_t));
    buf->next += sizeof(uint16_t);
    if(buf->next > buf->size) buf->size = buf->next;
}

void serial_buffer_push_u32(serial_buffer *buf, uint32_t val)
{
    serial_buffer_require(buf, sizeof(uint32_t));
    memcpy((uint32_t *) (buf->data + buf->next), &val, sizeof(uint32_t));
    buf->next += sizeof(uint32_t);
    if(buf->next > buf->size) buf->size = buf->next;
}

void serial_buffer_push_u64(serial_buffer *buf, uint64_t val)
{
    serial_buffer_require(buf, sizeof(uint64_t));
    memcpy((uint64_t *) (buf->data + buf->next), &val, sizeof(uint64_t));
    buf->next += sizeof(uint64_t);
    if(buf->next > buf->size) buf->size = buf->next;
}

void serial_buffer_push_mem(serial_buffer *buf, char *val, size_t len)
{
    serial_buffer_require(buf, len);
    memcpy((buf->data + buf->next), val, len);
    buf->next += len;
    if(buf->next > buf->size) buf->size = buf->next;
}

uint8_t serial_buffer_pop_u8(serial_buffer *buf)
{
    uint8_t val = *((uint8_t*) (buf->data + buf->next));
    buf->next += sizeof(uint8_t);
    return val;
}

uint16_t serial_buffer_pop_u16(serial_buffer *buf)
{
    uint16_t val = *((uint16_t*) (buf->data + buf->next));
    buf->next += sizeof(uint16_t);
    return val;
}

uint32_t serial_buffer_pop_u32(serial_buffer *buf)
{
    uint32_t val = *((uint32_t*) (buf->data + buf->next));
    buf->next += sizeof(uint32_t);
    return val;
}

uint64_t serial_buffer_pop_u64(serial_buffer *buf)
{
    uint64_t val = *((uint64_t*) (buf->data + buf->next));
    buf->next += sizeof(uint64_t);
    return val;
}

void serial_buffer_pop_mem(void *val, size_t len, serial_buffer *buf)
{
    memcpy(val, buf->data + buf->next, len);
    buf->next += len;
}
