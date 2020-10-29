#include <string.h>

// TODO: This is for htons
// Should be abstracted awayt in the network
// layer
#include <arpa/inet.h>

#include "network.h"
#include "crypto.h"
#include "proto.h"

// Bitcoin special field serialization
static void serialize_string(serial_buffer *buf, const char *str)
{
    for(size_t i=0; i<strlen(str); ++i) {
        serial_buffer_push_u8(buf, str[i]);
    }
}

static void serialize_port(serial_buffer *buf, uint16_t port)
{
    serial_buffer_push_u16(buf, htons(port));
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

static void serialize_header(bc_node *node, serial_buffer *message, char *cmd)
{
    // Magic number for testnet
    serial_buffer_push_u32(message, node->network->magic_number);
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

void send_version(bc_node *node, bc_msg_version *msg)
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
    message.next = 0;;
    serialize_header(node, &message, "version");
    
    send_message(node, &message);
    serial_buffer_destroy(&message);
}

void send_message(bc_node *node, serial_buffer *msg)
{
    send(node->socket, msg->data, msg->size, 0);
}
