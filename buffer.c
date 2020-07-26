#include <string.h>
#include <stdlib.h>
#include "buffer.h"

void buffer_init(buffer *buf)
{
    buf->capacity = 100;
    buf->data = calloc(buf->capacity, 1);
    buf->next = 0;
    buf->size = 0;
}

void buffer_destroy(buffer *buf)
{
    buf->capacity = 0;
    free(buf->data);
    buf->next = 0;
    buf->size = 0;
}

// Make sur there's at least size free bytes in the buffer
void buffer_require(buffer *buf, size_t size)
{ 
    if(((int)(buf->capacity - buf->next - size)) <= 0) {
        // Double buffer capacity
        size_t new_capacity = buf->capacity * 2;
        buf->data = realloc(buf->data, new_capacity);
        memset(buf->data+buf->capacity, 0, buf->capacity);
        buf->capacity = new_capacity;
    }
}

void buffer_push_u8(buffer *buf, unsigned char val)
{
    buffer_require(buf, 1);
    buf->data[buf->next] = val;
    buf->next++;
    if(buf->next > buf->size) buf->size = buf->next;
}

void buffer_push_u16(buffer *buf, uint16_t val)
{
    buffer_require(buf, sizeof(uint16_t));
    memcpy((uint16_t *) (buf->data + buf->next), &val, sizeof(uint16_t));
    buf->next += sizeof(uint16_t);
    if(buf->next > buf->size) buf->size = buf->next;
}

void buffer_push_u32(buffer *buf, uint32_t val)
{
    buffer_require(buf, sizeof(uint32_t));
    memcpy((uint32_t *) (buf->data + buf->next), &val, sizeof(uint32_t));
    buf->next += sizeof(uint32_t);
    if(buf->next > buf->size) buf->size = buf->next;
}

void buffer_push_u64(buffer *buf, uint64_t val)
{
    buffer_require(buf, sizeof(uint64_t));
    memcpy((uint64_t *) (buf->data + buf->next), &val, sizeof(uint64_t));
    buf->next += sizeof(uint64_t);
    if(buf->next > buf->size) buf->size = buf->next;
}
