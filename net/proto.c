#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "proto.h"
#include "../crypto/crypto.h"
#include "../config.h"

inline static uint16_t switch_endian_16(uint16_t val)
{
    return (((val & 0xff) << 8) | ((val & 0xff00) >> 8));
}

static uint32_t switch_endian_32(uint32_t val)
{
    return ((val & 0x000000ff) << 24)
         | ((val & 0x0000ff00) <<  8)
         | ((val & 0x00ff0000) >>  8)
         | ((val & 0xff000000) >> 24);
}

/*
//
// This function works but generate an unused warning 
//
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

void bc_proto_msg_destroy(bc_proto_msg *msg)
{
    free(msg);
}

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

static void deserialize_port(uint16_t *port, serial_buffer *buf)
{
    *port = switch_endian_16(serial_buffer_pop_u16(buf));
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

static void deserialize_ipv4(uint32_t *ip, serial_buffer *buf)
{
    // 10 zero bytes
    for(int i=0; i<10; ++i) {
        serial_buffer_pop_u8(buf);
    }
    
    // 2 ff bytes
    for(int i=0; i<2; ++i) {
        serial_buffer_pop_u8(buf);
    }
    
    // 4 IPv4 bytes
    *ip = switch_endian_32(serial_buffer_pop_u32(buf));
}

void serialize_header(serial_buffer *message, const char *cmd)
{
    // Magic number for testnet
    serial_buffer_push_u32(message, BC_TESTNET_MAGIC_NUM);
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

void deserialize_header(serial_buffer *msg, bc_proto_header *header)
{
    header->magic = serial_buffer_pop_u32(msg);
    serial_buffer_pop_mem(&header->command, 12, msg);
    header->payload_len = serial_buffer_pop_u32(msg);
    header->checksum = serial_buffer_pop_u32(msg);  // TODO Verify checksum
}

void bc_proto_net_addr_print(bc_proto_net_addr *n)
{
    printf("{Time: %x, Services: %lx, Ip: %lx, Port: %hu}",
            n->time, n->services, n->ip, n->port);
}


/////////////////////////////// PING //////////////////////////////////

void bc_proto_ping_serialize(bc_msg_ping *msg, serial_buffer *buf)
{
    buf->size = MESSAGE_HEADER_LEN;
    serial_buffer_push_u32(buf, msg->nonce);
    
    // Reset write head
    buf->next = 0;
    serialize_header(buf, "ping");
}

void bc_proto_ping_deserialize(bc_msg_ping *msg, serial_buffer *buf)
{
    msg->nonce = serial_buffer_pop_u64(buf);
}

void bc_proto_ping_print(bc_msg_ping *msg)
{
    printf("ping {\n\tNonce: %lx,\n}\n", msg->nonce);
}


/////////////////////////////// PONG //////////////////////////////////

void bc_proto_pong_serialize(bc_msg_pong *msg, serial_buffer *buf)
{
    buf->next += MESSAGE_HEADER_LEN;
    serial_buffer_push_u64(buf, msg->nonce);
    
    // Reset write head
    buf->next = 0;
    serialize_header(buf, "pong");
}

void bc_proto_pong_deserialize(bc_msg_pong *msg, serial_buffer *buf)
{
    msg->nonce = serial_buffer_pop_u64(buf);
}

void bc_proto_pong_print(bc_msg_pong *msg)
{
    printf("pong {\n\tNonce: %lx,\n}\n", msg->nonce);
}


///////////////////////////// VERACK ////////////////////////////////////

//void bc_proto_verack_send(bc_socket *socket)
void bc_proto_verack_serialize(serial_buffer *buf)
{
    // Since we don't the message is simply a header and we don't push 
    // any byte to it, let's update the message size manually so that 
    // serialize_header logic works. Bad hack
    // TODO FIX ME
    buf->size = MESSAGE_HEADER_LEN;
    serialize_header(buf, "verack");
}

void bc_proto_verack_print()
{
    printf("verack\n");
}


/////////////////////////////// VERSION ///////////////////////////////

//void bc_proto_version_send(bc_socket *socket, bc_msg_version *msg)
void bc_proto_version_serialize(bc_msg_version *msg, serial_buffer *buf)
{
    // Serialize msg
    //serial_buffer message;
    //serial_buffer_init(&message, 100);
    
    // TODO instead of this hack, just leave a 0 checksum and have
    // a checksum function at the end
    // Leave room for the message header that will be computed at the end
    buf->next += MESSAGE_HEADER_LEN;
    
    serial_buffer_push_u32(buf, msg->version);
    serial_buffer_push_u64(buf, msg->services);
    serial_buffer_push_u64(buf, msg->timestamp);
    serial_buffer_push_u64(buf, msg->dest.services);
    serialize_ipv4(buf, msg->dest.ip);
    serialize_port(buf, msg->dest.port);
    serial_buffer_push_u64(buf, msg->src.services);
    serialize_ipv4(buf, msg->src.ip);
    serialize_port(buf, msg->src.port);
    serial_buffer_push_u64(buf, msg->nonce);
    serial_buffer_push_u8(buf, strlen(msg->user_agent));
    serialize_string(buf, msg->user_agent);
    serial_buffer_push_u32(buf, msg->start_height);
    serial_buffer_push_u8(buf, msg->relay);
    
    // Reset write head
    buf->next = 0;
    serialize_header(buf, "version");
}

void bc_proto_version_deserialize(bc_msg_version *msg, serial_buffer *buf)
{
    msg->version = serial_buffer_pop_u32(buf);
    msg->services = serial_buffer_pop_u64(buf);
    msg->timestamp = serial_buffer_pop_u64(buf);
    // Dest
    msg->dest.services = serial_buffer_pop_u64(buf);
    msg->dest.time = 0; // Not present in version message
    deserialize_ipv4((uint32_t *) &(msg->dest.ip), buf);
    deserialize_port(&(msg->dest.port), buf);
    // Src
    msg->src.services = serial_buffer_pop_u64(buf);
    msg->src.time = 0; // Not present in version message
    deserialize_ipv4((uint32_t *) &(msg->src.ip), buf);
    deserialize_port(&(msg->src.port), buf);
    //
    msg->nonce = serial_buffer_pop_u64(buf);
    unsigned char user_agent_len = serial_buffer_pop_u8(buf);
    user_agent_len = (user_agent_len <= USER_AGENT_MAX_LEN) ? user_agent_len : USER_AGENT_MAX_LEN;
    serial_buffer_pop_mem(msg->user_agent, user_agent_len, buf);
    msg->start_height = serial_buffer_pop_u32(buf);
    msg->relay = serial_buffer_pop_u8(buf);
}

void bc_proto_version_print(bc_msg_version *msg)
{
    printf("version {\n\tVersion: %d,\n\tServices: %ld,\n\tTimestamp: %ld\n",
            msg->version, msg->services, msg->timestamp);
    printf("\tDest: ");
    bc_proto_net_addr_print(&msg->dest);
    printf("\n\tSrc: ");
    bc_proto_net_addr_print(&msg->src);
    printf("\n\tNonce: %lx,\n\tUser-Agent: %s\n\tStart height: %d,\n"
           "\tRelay: %d,\n}\n",
            msg->nonce, msg->user_agent, msg->start_height, msg->relay);
}
