#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <openssl/sha.h>

#include "buffer.h"

// TODO Implement dns based seeding
// Testnet seed dns
// seed.tbtc.petertodd.org
// testnet-seed.bitcoin.jonasschnelli.ch

typedef struct bc_network {
    uint32_t protocol_version;
    uint32_t magic_number;
    uint16_t port;
    int socket;
} bc_network;

const uint32_t protocol_version = 70015;
const char *user_agent = "/test:0.0.1/";
const size_t message_header_len = 24;
// Testnet
const uint32_t testnet_magic_number = 0x0709110b;
const uint16_t testnet_port = 18333;

#define REMOTE_NODE_ADDR "50.2.13.165" // Testnet

// Debug function that prints an hex dump of a buffer
void dump_hex(void *buff, size_t size)
{
    for(int i=0; i<size; ++i) {
        printf("%02x ", ((unsigned char *) buff)[i]);
    }
    printf("\n");
}

// Bitcoin special field serialization
void serialize_string(buffer *buf, const unsigned char *str)
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

uint64_t gen_nonce()
{
    srand(time(NULL));
    // Concatenate 2 32bit rand(), assumes rand() returns a 32 bit number
    return ((uint64_t) rand()) | (((uint64_t) rand()) << 32);
}

uint32_t gen_checksum(unsigned char *buf, size_t len)
{
    // The first 4 byte of a double sha256
    unsigned char checksum[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buf, len);
    SHA256_Final(checksum, &ctx);
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, checksum, SHA256_DIGEST_LENGTH);
    SHA256_Final(checksum, &ctx);
    return *((uint32_t *) checksum);
}

void serialize_header(bc_network *network, buffer *message, char *cmd)
{
    // Magic number for testnet
    buffer_push_u32(message, network->magic_number);
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

int send_version_cmd(bc_network *network)
{
    buffer message;
    buffer_init(&message);
    
    // Leave room for the message header that will be computed at the end
    message.next += message_header_len;
    
    // Version
    buffer_push_u32(&message, network->protocol_version);
    // Services
    buffer_push_u64(&message, 1);
    // Timestamp
    buffer_push_u64(&message, (uint64_t) time(NULL));
    // Destination address
    buffer_push_u64(&message, 1);
    serialize_ipv4(&message, REMOTE_NODE_ADDR);
    serialize_port(&message, network->port);
    // Source address
    buffer_push_u64(&message, 1);
    serialize_ipv4(&message, "0.0.0.0");
    serialize_port(&message, 0);
    // Random nonce
    buffer_push_u64(&message, gen_nonce());
    // User agent
    buffer_push_u8(&message, strlen(user_agent));
    serialize_string(&message, user_agent);
    // Start height, last block received by us
    buffer_push_u32(&message, 0);
    // Relay
    buffer_push_u8(&message, 1);
    
    // Reset write head
    message.next = 0;;
    serialize_header(network, &message, "version");
    
    send(network->socket, message.data, message.size, 0);
    buffer_destroy(&message);
    return 0;
}

int main(int argc, char **argv)
{
    bc_network network = {
        .protocol_version = protocol_version,
        .magic_number = testnet_magic_number,
        .port = testnet_port,
        .socket = 0
    };
    
    if((network.socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        printf("Socket creation error\n");
        return -1;
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(network.port);
    inet_pton(AF_INET, REMOTE_NODE_ADDR, &server_addr.sin_addr);
    
    if((connect(network.socket, (struct sockaddr *) &server_addr,
            sizeof(server_addr))) < 0) {
        printf("Connection Failed\n");
        return -1;
    }
    
    send_version_cmd(&network);
    printf("RECV-------------------------------------------\n\n");
    unsigned char message_buffer[2000] = {0};
    int len = recv(network.socket, message_buffer, 2000, 0);
    dump_hex(message_buffer, len);
    printf("RECV-------------------------------------------\n\n");
    len = recv(network.socket, message_buffer, 2000, 0);
    dump_hex(message_buffer, len);
    
    close(network.socket);
    return 0;
}
