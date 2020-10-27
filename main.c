#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>

#include "node.h"
#include "network.h"
#include "crypto.h"
#include "serial_buffer.h"
#include "dns.h"
#include "debug.h"

// Testnet seed dns
// seed.tbtc.petertodd.org
// testnet-seed.bitcoin.jonasschnelli.ch

const uint32_t protocol_version = 70015;
const char *user_agent = "/test:0.0.1/";
const size_t message_header_len = 24;

// Bitcoin special field serialization
void serialize_string(serial_buffer *buf, const char *str)
{
    for(size_t i=0; i<strlen(str); ++i) {
        serial_buffer_push_u8(buf, str[i]);
    }
}

void serialize_port(serial_buffer *buf, uint16_t port)
{
    serial_buffer_push_u16(buf, htons(port));
}

void serialize_ipv4(serial_buffer *buf, uint32_t ip)
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

void serialize_header(bc_node *node, serial_buffer *message, char *cmd)
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
    size_t payload_len = message->size - message_header_len;
    serial_buffer_push_u32(message, payload_len);
    // Checksum
    serial_buffer_push_u32(message, gen_checksum(message->data+message_header_len, payload_len));
}

int send_version_cmd(bc_node *node)
{
    serial_buffer message;
    serial_buffer_init(&message, 100);
    
    // Leave room for the message header that will be computed at the end
    message.next += message_header_len;
    
    // Version
    serial_buffer_push_u32(&message, node->protocol_version);
    // Services
    serial_buffer_push_u64(&message, 1);
    // Timestamp
    serial_buffer_push_u64(&message, (uint64_t) time(NULL));
    // Destination address
    serial_buffer_push_u64(&message, 1);
    serialize_ipv4(&message, node->ip);
    serialize_port(&message, node->port);
    // Source address
    serial_buffer_push_u64(&message, 1);
    serialize_ipv4(&message, 0);
    serialize_port(&message, 0);
    // Random nonce
    serial_buffer_push_u64(&message, gen_nonce_64());
    // User agent
    serial_buffer_push_u8(&message, strlen(user_agent));
    serialize_string(&message, user_agent);
    // Start height, last block received by us
    serial_buffer_push_u32(&message, 0);
    // Relay
    serial_buffer_push_u8(&message, 1);
    
    // Reset write head
    message.next = 0;;
    serialize_header(node, &message, "version");
    
    send(node->socket, message.data, message.size, 0);
    serial_buffer_destroy(&message);
    return 0;
}

int connect_to_remote(bc_node *remote)
{
    if((remote->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        printf("Socket creation error\n");
        return -1;
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(remote->port);
    memcpy(&server_addr.sin_addr, &remote->ip, sizeof(remote->ip));
    
    if((connect(remote->socket, (struct sockaddr *) &server_addr,
            sizeof(server_addr))) < 0) {
        printf("Connection Failed\n");
        return -1;
    }
    
    remote->connected = true;
    return 0;
}

int disconnect_from_remote(bc_node *remote)
{
    close(remote->socket);
    return 0;
}

void handshake(bc_node node)
{
    send_version_cmd(&node);
    
    printf("RECV-------------------------------------------\n");
    unsigned char message_buffer[2000] = {0};
    // TODO Custom recv that gets a full message
    int len = recv(node.socket, message_buffer, 2000, 0);
    dump_hex(message_buffer, len);
    printf("END-------------------------------------------\n");
}

int main()
{
    // TODO creat a global bitcoin object and init it
    // initialization should fetch a bunch of potential client ips 
    // into a list.
    // TODO Try to connect to a specified number of ndoes
    
    // Get a potential ip for a remote node
    dns_record_a a_rec;
    dns_get_records_a("seed.tbtc.petertodd.org", &a_rec);
   
    bc_network testnet = {
        .magic_number = testnet_magic_number,
        .default_port = testnet_port,
    };
    
    bc_node remote = {
        .network = &testnet,
        .protocol_version = protocol_version,
        .ip = a_rec.ip,
        .port = testnet.default_port,
        .socket = 0,
        .connected = false
    };
    
    if(connect_to_remote(&remote) < 0) {
        return -1;
    }
    
    handshake(remote);
    
    disconnect_from_remote(&remote);
    return 0;
}
