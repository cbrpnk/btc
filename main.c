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

// TODO Implement dns based seeding
// Testnet seed dns
// seed.tbtc.petertodd.org
// testnet-seed.bitcoin.jonasschnelli.ch

#define PROTO_VERSION 60002
#define LOCAL_NODE_ADDR "0.0.0.0"
#define LOCAL_NODE_PORT 18333
#define REMOTE_NODE_ADDR "95.216.36.213"
#define REMOTE_NODE_PORT 18333
#define SUPPORTED_SERVICES 1 // NODE_NETWORK

uint64_t generate_nonce()
{
    // Concatenate 2 32bit rand(), assumes rand() returns a 32 bit number
    return ((uint64_t) rand()) | (((uint64_t) rand()) << 32);
}

// Debug function that prints an hex dump of a buffer
void dump_hex(void *buff, size_t size)
{
    for(int i=0; i<size; ++i) {
        printf("%02x ", ((unsigned char *) buff)[i]);
        //printf("%c ", ((unsigned char *) buff)[i]);
    }
    printf("\n");
}

// Serialize builtin types
void serialize_byte(unsigned char **buf, unsigned char val)
{
    **buf = val;
    (*buf)++;
}

void serialize_short(unsigned char **buf, uint16_t val)
{
    memcpy((uint16_t *) *buf, &val, sizeof(uint16_t));
    *buf += sizeof(uint16_t);
}

void serialize_long(unsigned char **buf, uint32_t val)
{
    memcpy((uint32_t *) *buf, &val, sizeof(uint32_t));
    *buf += sizeof(uint32_t);
}

void serialize_long_long(unsigned char **buf, uint64_t val)
{
    memcpy((uint64_t *) *buf, &val, sizeof(uint64_t));
    *buf += sizeof(uint64_t);
}

// Bitcoin special field serialization
void serialize_ipv4(unsigned char **buf, const char* ipstr)
{
    // 10 zero bytes
    for(int i=0; i<10; ++i) {
        serialize_byte(buf, 0x00);
    }
    
    // 2 ff bytes
    for(int i=0; i<2; ++i) {
        serialize_byte(buf, 0xff);
    }
    
    // 4 IPv4 byte Big Endian
    //unsigned char addr[4];
    //inet_pton(AF_INET, ipstr, addr);
    for(int i=3; i>=0; --i) {
        //serialize_byte(buf, addr[i]);
        serialize_byte(buf, 0x00);
    }
}

void serialize_port(unsigned char **buf, uint16_t port)
{
    serialize_short(buf, htons(port));
}

void serialize_header(unsigned char **header, unsigned char *payload, char *cmd, size_t payload_len)
{
    printf("Serialize header\n");
    // Magic number for testnet
    serialize_byte(header, 0x0b);
    serialize_byte(header, 0x11);
    serialize_byte(header, 0x09);
    serialize_byte(header, 0x07);
    // TODO Test if cmd length is smaller than 12
    // Command
    for(int i=0; i<strlen(cmd); ++i) {
        serialize_byte(header, cmd[i]);
    }
    // Command padding
    *header += 12-strlen(cmd);
    // Payload len
    serialize_long(header, payload_len);
    // Checksum
    unsigned char *checksum = SHA256(payload, payload_len, 0);
    checksum = SHA256(checksum, strlen(checksum), 0);
    serialize_long(header, *((uint32_t *) checksum));
}

int send_version_cmd(int sock)
{
    // The payload length can change based on the size of the user-agent field
    const unsigned int header_len = 24;
    const unsigned int payload_len = 85;
    const unsigned int message_len = header_len + payload_len;
    unsigned char *message = calloc(message_len, 1);
    
    // The header and payload pointers will be advanced accordingly in the serialize functions
    unsigned char *header = message;
    unsigned char *payload = message + header_len;
    
    // Version
    serialize_long(&payload, PROTO_VERSION);
    // Services
    serialize_long_long(&payload, SUPPORTED_SERVICES);
    // Timestamp
    serialize_long_long(&payload, (uint64_t) time(NULL));
    // Destination address
    serialize_long_long(&payload, SUPPORTED_SERVICES);
    serialize_ipv4(&payload, REMOTE_NODE_ADDR);
    serialize_port(&payload, 0);
    // Source address
    serialize_long_long(&payload, SUPPORTED_SERVICES);
    serialize_ipv4(&payload, LOCAL_NODE_ADDR);
    serialize_port(&payload, 0);
    // Random nonce
    serialize_long_long(&payload, generate_nonce());
    // User agent
    serialize_byte(&payload, 0x00);
    // Start height, last block received by us
    serialize_long(&payload, 0);
    
    // Header
    serialize_header(&header, payload, "version", payload_len);
    
    dump_hex(message, message_len);
    send(sock, message, message_len, 0);
    free(message);
    return 0;
}

int main(int argc, char **argv)
{
    int sock = 0;
    
    if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        printf("Socket creation error\n");
        return -1;
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(REMOTE_NODE_PORT);
    inet_pton(AF_INET, REMOTE_NODE_ADDR, &server_addr.sin_addr);
    
    if((connect(sock, (struct sockaddr *) &server_addr, sizeof(server_addr))) < 0) {
        printf("Connection Failed\n");
        return -1;
    }
    
    send_version_cmd(sock);
    printf("RECV-------------------------------------------\n\n");
    unsigned char message_buffer[2000] = {0};
    int len = recv(sock, message_buffer, 2000, 0);
    printf("%d\n", len);
    dump_hex(message_buffer, len);
    
    close(sock);
    return 0;
}
