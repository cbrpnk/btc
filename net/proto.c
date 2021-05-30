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

/*
static uint32_t switch_endian_32(uint32_t val)
{
    return ((val & 0x000000ff) << 24)
         | ((val & 0x0000ff00) <<  8)
         | ((val & 0x00ff0000) >>  8)
         | ((val & 0xff000000) >> 24);
}

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
    *ip = serial_buffer_pop_u32(buf);
}

void bc_proto_serialize_header(serial_buffer *message, const char *cmd)
{
    // Calculate payload_len early so that message->size is not affected
    // by our searial push TODO HACK
    size_t payload_len = 0;
    if(message->size > 0) {
        payload_len = message->size - MESSAGE_HEADER_LEN;
    }
    
    // Magic number for testnet
    serial_buffer_push_u32(message, BC_MAGIC_NUM);
    // TODO Test if cmd length is smaller than 12
    // Command
    for(size_t i=0; i<strlen(cmd); ++i) {
        serial_buffer_push_u8(message, cmd[i]);
    }
    // Command padding
    message->next += 12-strlen(cmd);
    // Payload len
    serial_buffer_push_u32(message, payload_len);
    // Checksum
    serial_buffer_push_u32(
        message,
        gen_checksum(message->data+MESSAGE_HEADER_LEN,payload_len)
    );
}

void bc_proto_deserialize_header(serial_buffer *msg, bc_proto_header *header)
{
    header->magic = serial_buffer_pop_u32(msg);
    serial_buffer_pop_mem(&header->command, 12, msg);
    header->payload_len = serial_buffer_pop_u32(msg);
    header->checksum = serial_buffer_pop_u32(msg);
}

void bc_proto_net_addr_print(bc_proto_net_addr *n)
{
    printf("{Time: %x, Services: %lx, Ip: %s, Port: %hu}",
            n->time, n->services, inet_ntoa(*((struct in_addr *) &(n->ip))), n->port);
}


//////////////////// Variable length fields //////////////////////////

void bc_proto_varint_deserialize(uint64_t *out, serial_buffer *buf)
{
    uint8_t first_byte = serial_buffer_pop_u8(buf);
    if(first_byte < 0xfd) {
        *out = first_byte;
    } else if(first_byte == 0xfd) {
        *out = serial_buffer_pop_u16(buf);
    } else if(first_byte == 0xfe) {
        *out = serial_buffer_pop_u32(buf);
    } else if(first_byte == 0xff) {
        *out = serial_buffer_pop_u64(buf);
    }
}

/////////////////////////////// Msg /////////////////////////////////

bc_msg *bc_msg_new_from_buffer(serial_buffer *buf)
{
    bc_msg *msg = NULL;
    bc_proto_header header;
    bc_proto_deserialize_header(buf, &header);
    
    // Verify checksum
    uint32_t checksum = gen_checksum(buf->data+MESSAGE_HEADER_LEN,
                            header.payload_len);
    
    if(header.checksum == checksum) {
        if(strcmp(header.command, "inv") == 0) {
            msg = (bc_msg *) bc_msg_inv_new();
            bc_msg_inv_deserialize((bc_msg_inv *) msg, buf);
        } else if(strcmp(header.command, "ping") == 0) {
            msg = (bc_msg *) bc_msg_ping_new();
            bc_msg_ping_deserialize((bc_msg_ping *) msg, buf);
        } else if(strcmp(header.command, "pong") == 0) {
            msg = (bc_msg *) bc_msg_pong_new();
            bc_msg_pong_deserialize((bc_msg_pong *) msg, buf);
        } else if(strcmp(header.command, "sendcmpct") == 0) {
            msg = (bc_msg *) bc_msg_sendcmpct_new();
            bc_msg_sendcmpct_deserialize((bc_msg_sendcmpct *) msg, buf);
        } else if(strcmp(header.command, "version") == 0) {
            msg = (bc_msg *) bc_msg_version_new();
            bc_msg_version_deserialize((bc_msg_version *) msg, buf);
        } else if(strcmp(header.command, "verack") == 0) {
            msg = (bc_msg *) bc_msg_verack_new();
        } else {
            printf("%s [TODO]\n", header.command);
        }
    }
    
    return msg;
}

void bc_msg_destroy(bc_msg *msg)
{
    switch(msg->type) {
    case BC_MSG_INV:
        bc_msg_inv_destroy((bc_msg_inv *) msg);
        break;
    case BC_MSG_PING:
        bc_msg_ping_destroy((bc_msg_ping *) msg);
        break;
    case BC_MSG_PONG:
        bc_msg_pong_destroy((bc_msg_pong *) msg);
        break;
    case BC_MSG_SENDCMPCT:
        bc_msg_sendcmpct_destroy((bc_msg_sendcmpct *) msg);
        break;
    case BC_MSG_VERACK:
        bc_msg_verack_destroy((bc_msg_verack *) msg);
        break;
    case BC_MSG_VERSION:
        bc_msg_version_destroy((bc_msg_version *) msg);
        break;
    }
}

void bc_msg_serialize(bc_msg *msg, serial_buffer *buf)
{
    switch(msg->type) {
    case BC_MSG_INV:
        bc_msg_inv_serialize((bc_msg_inv *) msg, buf);
        break;
    case BC_MSG_PING:
        bc_msg_ping_serialize((bc_msg_ping *) msg, buf);
        break;
    case BC_MSG_PONG:
        bc_msg_pong_serialize((bc_msg_pong *) msg, buf);
        break;
    case BC_MSG_SENDCMPCT:
        bc_msg_sendcmpct_serialize((bc_msg_sendcmpct *) msg, buf);
        break;
    case BC_MSG_VERACK:
        bc_msg_verack_serialize(buf);
        break;
    case BC_MSG_VERSION:
        bc_msg_version_serialize((bc_msg_version *) msg, buf);
        break;
    }
}

void bc_msg_print(bc_msg *msg)
{
    switch(msg->type) {
    case BC_MSG_INV:
        bc_msg_inv_print((bc_msg_inv *) msg);
        break;
    case BC_MSG_PING:
        bc_msg_ping_print((bc_msg_ping *) msg);
        break;
    case BC_MSG_PONG:
        bc_msg_pong_print((bc_msg_pong *) msg);
        break;
    case BC_MSG_SENDCMPCT:
        bc_msg_sendcmpct_print((bc_msg_sendcmpct *) msg);
        break;
    case BC_MSG_VERACK:
        bc_msg_verack_print();
        break;
    case BC_MSG_VERSION:
        bc_msg_version_print((bc_msg_version *) msg);
        break;
    }
}

/////////////////////////////// Inv ///////////////////////////////////

bc_msg_inv *bc_msg_inv_new()
{
    bc_msg_inv *msg = calloc(1, sizeof(bc_msg_inv));
    msg->type = BC_MSG_INV;
    msg->count = 0;
    msg->vec = NULL;
    return msg;
}

void bc_msg_inv_destroy(bc_msg_inv *msg)
{
    if(msg->vec) {
        free(msg->vec);
    }
    free(msg);
}

void bc_msg_inv_serialize(bc_msg_inv *msg, serial_buffer *buf)
{
    buf->size = MESSAGE_HEADER_LEN;
    
    serial_buffer_push_u64(buf, msg->count);
    for(uint64_t i=0; i<msg->count; ++i) {
        serial_buffer_push_u32(buf, msg->vec[i].type);
        serial_buffer_push_mem(buf, msg->vec[i].hash, BC_SHA256_LEN);
    }
    
    // Reset write head
    buf->next = 0;
    bc_proto_serialize_header(buf, "inv");
}

void bc_msg_inv_deserialize(bc_msg_inv *msg, serial_buffer *buf)
{
    bc_proto_varint_deserialize(&msg->count, buf);
    msg->vec = malloc(sizeof(bc_msg_inv_vec) * msg->count);
    for(uint64_t i=0; i<msg->count; ++i) {
        msg->vec[i].type = serial_buffer_pop_u32(buf);
        serial_buffer_pop_mem(&(msg->vec[i].hash), 32, buf);
    }
}

void bc_msg_inv_print(bc_msg_inv *msg)
{
    printf("inv {\n\tcount: %ld,\n\tvec: {\n", msg->count);
    for(uint64_t i=0; i<msg->count; ++i) {
        // Print Type
        printf("\t\ttype: ");
        switch(msg->vec[i].type) {
        case BC_MSG_INV_ERROR:
            printf("ERROR");
            break;
        case BC_MSG_INV_TX:
            printf("TX");
            break;
        case BC_MSG_INV_BLOCK:
            printf("BLOCK");
            break;
        case BC_MSG_INV_FILTERED_BLOCK:
            printf("FILTERED_BLOCK");
            break;
        case BC_MSG_INV_CMPCT_BLOCK:
            printf("CMPCT_BLOCK");
            break;
        case BC_MSG_INV_WITNESS_TX:
            printf("WITNESS_TX");
            break;
        case BC_MSG_INV_WITNESS_BLOCK:
            printf("WITNESS_BLOCK");
            break;
        case BC_MSG_INV_WITNESS_FILTERED_BLOCK:
            printf("WITNESS_FILTERED_BLOCK");
            break;
        }
        printf(",\n");
        
        // Print Hash
        printf("\t\thash: ");
        for(int j=31; j>=0; --j) {
            printf("%02x", (uint8_t) msg->vec[i].hash[j]);
        }
        printf(",\n\t}\n");
    }
    printf("}\n");
}

/////////////////////////////// Ping //////////////////////////////////

bc_msg_ping *bc_msg_ping_new()
{
    bc_msg_ping *msg = calloc(1, sizeof(bc_msg_ping));
    msg->type = BC_MSG_PING;
    return msg;
}

void bc_msg_ping_destroy(bc_msg_ping *msg)
{
    free(msg);
}

void bc_msg_ping_serialize(bc_msg_ping *msg, serial_buffer *buf)
{
    buf->size = MESSAGE_HEADER_LEN;
    serial_buffer_push_u32(buf, msg->nonce);
    
    // Reset write head
    buf->next = 0;
    bc_proto_serialize_header(buf, "ping");
}

void bc_msg_ping_deserialize(bc_msg_ping *msg, serial_buffer *buf)
{
    msg->nonce = serial_buffer_pop_u64(buf);
}

void bc_msg_ping_print(bc_msg_ping *msg)
{
    printf("ping {\n\tNonce: %lx,\n}\n", msg->nonce);
}


/////////////////////////////// Pong //////////////////////////////////

bc_msg_pong *bc_msg_pong_new()
{
    bc_msg_pong *msg = calloc(1, sizeof(bc_msg_pong));
    msg->type = BC_MSG_PONG;
    return msg;
}

void bc_msg_pong_destroy(bc_msg_pong *msg)
{
    free(msg);
}

void bc_msg_pong_serialize(bc_msg_pong *msg, serial_buffer *buf)
{
    buf->next += MESSAGE_HEADER_LEN;
    serial_buffer_push_u64(buf, msg->nonce);
    
    // Reset write head
    buf->next = 0;
    bc_proto_serialize_header(buf, "pong");
}

void bc_msg_pong_deserialize(bc_msg_pong *msg, serial_buffer *buf)
{
    msg->nonce = serial_buffer_pop_u64(buf);
}

void bc_msg_pong_print(bc_msg_pong *msg)
{
    printf("pong {\n\tNonce: %lx,\n}\n", msg->nonce);
}


///////////////////////////// Sendcmpct //////////////////////////////////

bc_msg_sendcmpct *bc_msg_sendcmpct_new()
{
    bc_msg_sendcmpct *msg = calloc(1, sizeof(bc_msg_sendcmpct));
    msg->type = BC_MSG_SENDCMPCT;
    return msg;
}

void bc_msg_sendcmpct_destroy(bc_msg_sendcmpct *msg)
{
    free(msg);
}

void bc_msg_sendcmpct_serialize(bc_msg_sendcmpct *msg, serial_buffer *buf)
{
    buf->next += MESSAGE_HEADER_LEN;
    serial_buffer_push_u8(buf, msg->is_compact);
    serial_buffer_push_u64(buf, msg->version);
    
    // Reset write head
    buf->next = 0;
    bc_proto_serialize_header(buf, "sendcmpct");
}

void bc_msg_sendcmpct_deserialize(bc_msg_sendcmpct *msg, serial_buffer *buf)
{
    msg->is_compact = serial_buffer_pop_u8(buf);
    msg->version = serial_buffer_pop_u64(buf);
}

void bc_msg_sendcmpct_print(bc_msg_sendcmpct *msg)
{
    printf("sendcmpct {\n\tCompact: %d,\n\tVersion: %ld\n}\n",
            msg->is_compact, msg->version);
}


///////////////////////////// Verack ////////////////////////////////////

bc_msg_verack *bc_msg_verack_new()
{
    bc_msg_verack *msg = calloc(1, sizeof(bc_msg_verack));
    msg->type = BC_MSG_VERACK;
    return msg;
}

void bc_msg_verack_destroy(bc_msg_verack *msg)
{
    free(msg);
}

void bc_msg_verack_serialize(serial_buffer *buf)
{
    bc_proto_serialize_header(buf, "verack");
}

void bc_msg_verack_print()
{
    printf("verack\n");
}


/////////////////////////////// Version ///////////////////////////////

bc_msg_version *bc_msg_version_new()
{
    bc_msg_version *msg = calloc(1, sizeof(bc_msg_version));
    msg->type = BC_MSG_VERSION;
    return msg;
}

void bc_msg_version_destroy(bc_msg_version *msg)
{
    free(msg);
}

void bc_msg_version_serialize(bc_msg_version *msg, serial_buffer *buf)
{
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
    bc_proto_serialize_header(buf, "version");
}

void bc_msg_version_deserialize(bc_msg_version *msg, serial_buffer *buf)
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

void bc_msg_version_print(bc_msg_version *msg)
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
