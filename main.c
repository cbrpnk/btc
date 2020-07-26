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

//#define MAGIC_NUMBER 0xd9b4bef9 // Main net
#define HEADER_LEN 24
#define USER_AGENT "/test:0.0.1/"
#define MAGIC_NUMBER 0x0709110b// Testnet 3
#define PROTO_VERSION 70015
#define LOCAL_NODE_ADDR "0.0.0.0"
#define LOCAL_NODE_PORT 18333
//#define REMOTE_NODE_ADDR "95.216.36.213" // Testnet
//#define REMOTE_NODE_ADDR "43.245.223.150" // Testnet
#define REMOTE_NODE_ADDR "50.2.13.165" // Testnet
//#define REMOTE_NODE_ADDR "127.0.0.1" // Testnet
//#define REMOTE_NODE_ADDR "202.187.149.107"
#define REMOTE_NODE_PORT 18333
#define SUPPORTED_SERVICES 0x0408

// Debug function that prints an hex dump of a buffer
void dump_hex(void *buff, size_t size)
{
    for(int i=0; i<size; ++i) {
        printf("%02x ", ((unsigned char *) buff)[i]);
    }
    printf("\n");
}

// Buffer serialization
typedef struct buffer {
    unsigned char *data;
    // Index of the next byte to write
    unsigned int next;
    size_t size;
    size_t capacity;
} buffer;

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

void serialize_byte(buffer *buf, unsigned char val)
{
    buffer_require(buf, 1);
    buf->data[buf->next] = val;
    buf->next++;
    if(buf->next > buf->size) buf->size = buf->next;
}

void serialize_short(buffer *buf, uint16_t val)
{
    buffer_require(buf, sizeof(uint16_t));
    memcpy((uint16_t *) (buf->data + buf->next), &val, sizeof(uint16_t));
    buf->next += sizeof(uint16_t);
    if(buf->next > buf->size) buf->size = buf->next;
}

void serialize_long(buffer *buf, uint32_t val)
{
    buffer_require(buf, sizeof(uint32_t));
    memcpy((uint32_t *) (buf->data + buf->next), &val, sizeof(uint32_t));
    buf->next += sizeof(uint32_t);
    if(buf->next > buf->size) buf->size = buf->next;
}

void serialize_long_long(buffer *buf, uint64_t val)
{
    buffer_require(buf, sizeof(uint64_t));
    memcpy((uint64_t *) (buf->data + buf->next), &val, sizeof(uint64_t));
    buf->next += sizeof(uint64_t);
    if(buf->next > buf->size) buf->size = buf->next;
}

// Bitcoin special field serialization
void serialize_string(buffer *buf, const unsigned char *str)
{
    for(int i=0; i<strlen(str); ++i) {
        serialize_byte(buf, str[i]);
    }
}

void serialize_port(buffer *buf, uint16_t port)
{
    serialize_short(buf, htons(port));
}

void serialize_ipv4(buffer *buf, const char* ipstr)
{
    // 10 zero bytes
    for(int i=0; i<10; ++i) {
        serialize_byte(buf, 0x00);
    }
    
    // 2 ff bytes
    for(int i=0; i<2; ++i) {
        serialize_byte(buf, 0xff);
    }
    
    // 4 IPv4 bytes
    unsigned char addr[4];
    inet_pton(AF_INET, ipstr, addr);
    for(int i=0; i<4; ++i) {
        serialize_byte(buf, addr[i]);
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

void serialize_header(buffer *message, char *cmd)
{
    // Magic number for testnet
    serialize_long(message, MAGIC_NUMBER);
    // TODO Test if cmd length is smaller than 12
    // Command
    for(int i=0; i<strlen(cmd); ++i) {
        serialize_byte(message, cmd[i]);
    }
    // Command padding
    message->next += 12-strlen(cmd);
    // Payload len
    size_t payload_len = message->size - HEADER_LEN;
    serialize_long(message, payload_len);
    // Checksum
    serialize_long(message, gen_checksum(message->data+HEADER_LEN, payload_len));
}

int send_version_cmd(int sock)
{
    buffer message;
    buffer_init(&message);
    
    // Leave room for the message header that will be computed at the end
    message.next += HEADER_LEN;
    
    // Version
    serialize_long(&message, PROTO_VERSION);
    // Services
    serialize_long_long(&message, 1);
    // Timestamp
    serialize_long_long(&message, (uint64_t) time(NULL));
    // Destination address
    serialize_long_long(&message, 1);
    serialize_ipv4(&message, REMOTE_NODE_ADDR);
    serialize_port(&message, REMOTE_NODE_PORT);
    // Source address
    serialize_long_long(&message, 1);
    serialize_ipv4(&message, "0.0.0.0");
    serialize_port(&message, 0);
    // Random nonce
    serialize_long_long(&message, gen_nonce());
    // User agent
    serialize_byte(&message, strlen(USER_AGENT));
    serialize_string(&message, USER_AGENT);
    // Start height, last block received by us
    serialize_long(&message, 0);
    // Relay
    serialize_byte(&message, 1);
    
    // Reset write head
    message.next = 0;;
    serialize_header(&message, "version");
    
    send(sock, message.data, message.size, 0);
    buffer_destroy(&message);
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
    dump_hex(message_buffer, len);
    
    close(sock);
    return 0;
}
