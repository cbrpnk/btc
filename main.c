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

#include "crypto.h"
#include "buffer.h"
#include "dns.h"
#include "debug.h"

// TODO Implement dns based seeding
// Testnet seed dns
// seed.tbtc.petertodd.org
// testnet-seed.bitcoin.jonasschnelli.ch

const uint32_t protocol_version = 70015;
const char *user_agent = "/test:0.0.1/";
const size_t message_header_len = 24;
// Testnet
const uint32_t testnet_magic_number = 0x0709110b;
const uint16_t testnet_port = 18333;

/*
typedef struct bc_socket {
    char ip[15];
    uint16_t port;
    int id;
} bc_socket;

typedef struct bc_connection {
    bc_network *network;
} bc_connection;
*/

typedef struct bc_network {
    uint32_t magic_number;
    uint16_t default_port;
} bc_network;

typedef struct bc_node {
    bc_network *network;
    uint32_t protocol_version;
    char ip[15];
    uint16_t port;
    int socket;
    bool connected;
} bc_node;

// Bitcoin special field serialization
void serialize_string(buffer *buf, const char *str)
{
    for(int i=0; i<strlen(str); ++i) {
        buffer_push_u8(buf, str[i]);
    }
}

void serialize_port(buffer *buf, uint16_t port)
{
    buffer_push_u16(buf, htons(port));
}

void serialize_ipv4(buffer *buf, const char* ipstr)
{
    // 10 zero bytes
    for(int i=0; i<10; ++i) {
        buffer_push_u8(buf, 0x00);
    }
    
    // 2 ff bytes
    for(int i=0; i<2; ++i) {
        buffer_push_u8(buf, 0xff);
    }
    
    // 4 IPv4 bytes
    unsigned char addr[4];
    inet_pton(AF_INET, ipstr, addr);
    for(int i=0; i<4; ++i) {
        buffer_push_u8(buf, addr[i]);
        //serialize_byte(buf, 0x00);
    }
}

void serialize_header(bc_node *node, buffer *message, char *cmd)
{
    // Magic number for testnet
    buffer_push_u32(message, node->network->magic_number);
    // TODO Test if cmd length is smaller than 12
    // Command
    for(int i=0; i<strlen(cmd); ++i) {
        buffer_push_u8(message, cmd[i]);
    }
    // Command padding
    message->next += 12-strlen(cmd);
    // Payload len
    size_t payload_len = message->size - message_header_len;
    buffer_push_u32(message, payload_len);
    // Checksum
    buffer_push_u32(message, gen_checksum(message->data+message_header_len, payload_len));
}

int send_version_cmd(bc_node *node)
{
    buffer message;
    buffer_init(&message);
    
    // Leave room for the message header that will be computed at the end
    message.next += message_header_len;
    
    // Version
    buffer_push_u32(&message, node->protocol_version);
    // Services
    buffer_push_u64(&message, 1);
    // Timestamp
    buffer_push_u64(&message, (uint64_t) time(NULL));
    // Destination address
    buffer_push_u64(&message, 1);
    serialize_ipv4(&message, node->ip);
    serialize_port(&message, node->port);
    // Source address
    buffer_push_u64(&message, 1);
    serialize_ipv4(&message, "0.0.0.0");
    serialize_port(&message, 0);
    // Random nonce
    buffer_push_u64(&message, gen_nonce_64());
    // User agent
    buffer_push_u8(&message, strlen(user_agent));
    serialize_string(&message, user_agent);
    // Start height, last block received by us
    buffer_push_u32(&message, 0);
    // Relay
    buffer_push_u8(&message, 1);
    
    // Reset write head
    message.next = 0;;
    serialize_header(node, &message, "version");
    
    send(node->socket, message.data, message.size, 0);
    buffer_destroy(&message);
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
    inet_pton(AF_INET, remote->ip, &server_addr.sin_addr);
    
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

int main(int argc, char **argv)
{
    /*
    bc_network testnet = {
        .magic_number = testnet_magic_number,
        .default_port = testnet_port,
    };
    
    bc_node remote = {
        .network = &testnet,
        .protocol_version = protocol_version,
        .ip = "50.2.13.165",
        .port = testnet.default_port,
        .socket = 0,
        .connected = false
    };
    
    if(connect_to_remote(&remote) < 0) {
        return -1;
    }
    
    send_version_cmd(&remote);
    
    printf("RECV-------------------------------------------\n\n");
    unsigned char message_buffer[2000] = {0};
    int len = recv(remote.socket, message_buffer, 2000, 0);
    dump_hex(message_buffer, len);
    printf("RECV-------------------------------------------\n\n");
    len = recv(remote.socket, message_buffer, 2000, 0);
    dump_hex(message_buffer, len);
    
    disconnect_from_remote(&remote);
    */
    
    test_dns();
    return 0;
}
