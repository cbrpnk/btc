#include <string.h>
#include <stdint.h>

#include "crypto.h"
#include "proto.h"

inline static uint16_t switch_endian_16(uint16_t val)
{
    return (((val & 0xff) << 8) | ((val & 0xff00) >> 8));
}

/*
 
    //
    // These functions work but generate an unused warning 
    //
 
static uint32_t switch_endian_32(uint32_t val)
{
    return ((val & 0x000000ff) << 24)
         | ((val & 0x0000ff00) <<  8)
         | ((val & 0x00ff0000) >>  8)
         | ((val & 0xff000000) >> 24);
}

static uint64_t switch_endian_64(uint64_t val)
{
    return ((val & 0x00000000000000ff) << 56)
         | ((val & 0x000000000000ff00) << 40)
         | ((val & 0x0000000000ff0000) << 24)
         | ((val & 0x00000000ff000000) <<  8)
         | ((val & 0x000000ff00000000) >>  8)
         | ((val & 0x0000ff0000000000) >> 24)
         | ((val & 0x00ff000000000000) >> 40)
         | ((val & 0xff00000000000000) >> 56);
}
*/

// Bitcoin special field serialization
static void serialize_string(serial_buffer *buf, const char *str)
{
    for(size_t i=0; i<strlen(str); ++i) {
        serial_buffer_push_u8(buf, str[i]);
    }
}

static void serialize_port(serial_buffer *buf, uint16_t port)
{
    serial_buffer_push_u16(buf, switch_endian_16(port));
}

static void serialize_ipv4(serial_buffer *buf, uint32_t ip)
{
    // 10 zero bytes
    for(int i=0; i<10; ++i) {
        serial_buffer_push_u8(buf, 0x00);
    }
    
    // 2 ff bytes
    for(int i=0; i<2; ++i) {
        serial_buffer_push_u8(buf, 0xff);
    }
    
    // 4 IPv4 bytes
    serial_buffer_push_u32(buf, ip);
}

static void serialize_header(serial_buffer *message, char *cmd)
{
    // Magic number for testnet
    serial_buffer_push_u32(message, 0x0709110b); // TODO Pull that from config
    // TODO Test if cmd length is smaller than 12
    // Command
    for(size_t i=0; i<strlen(cmd); ++i) {
        serial_buffer_push_u8(message, cmd[i]);
    }
    // Command padding
    message->next += 12-strlen(cmd);
    // Payload len
    size_t payload_len = message->size - MESSAGE_HEADER_LEN;
    serial_buffer_push_u32(message, payload_len);
    // Checksum
    serial_buffer_push_u32(
        message,
        gen_checksum(message->data+MESSAGE_HEADER_LEN,payload_len)
    );
}

#include <stdio.h>
void bc_proto_send_version(bc_socket *socket, bc_msg_version *msg)
{
    // Serialize msg
    serial_buffer message;
    serial_buffer_init(&message, 100);
    
    // Leave room for the message header that will be computed at the end
    message.next += MESSAGE_HEADER_LEN;
    
    serial_buffer_push_u32(&message, msg->version);
    serial_buffer_push_u64(&message, msg->services);
    serial_buffer_push_u64(&message, msg->timestamp);
    serial_buffer_push_u64(&message, msg->dest.services);
    serialize_ipv4(&message, msg->dest.ip);
    serialize_port(&message, msg->dest.port);
    serial_buffer_push_u64(&message, msg->src.services);
    serialize_ipv4(&message, msg->src.ip);
    serialize_port(&message, msg->src.port);
    serial_buffer_push_u64(&message, msg->nonce);
    serial_buffer_push_u8(&message, strlen(msg->user_agent));
    serialize_string(&message, msg->user_agent);
    serial_buffer_push_u32(&message, msg->start_height);
    serial_buffer_push_u8(&message, msg->relay);
    
    // Reset write head
    message.next = 0;
    serialize_header(&message, "version");
    
    bc_proto_send_message(socket, &message);
    serial_buffer_destroy(&message);
}

void bc_proto_send_message(bc_socket *socket, serial_buffer *msg)
{
    bc_socket_send(socket, msg->data, msg->size);
}
