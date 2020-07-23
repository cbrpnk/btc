#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

// TODO Implement dns based seeding
// Testnet seed dns
// seed.tbtc.petertodd.org
// testnet-seed.bitcoin.jonasschnelli.ch

#define PROTO_VERSION 31402
#define REMOTE_NODE_ADDR "165.22.49.1"
#define REMOTE_NODE_PORT 18333
#define SUPPORTED_SERVICES 1 // NODE_NETWORK


// 64 bit variants of endian convertion functions
uint64_t htonll(uint64_t hostll)
{
    unsigned char *p = (unsigned char*) &hostll;
    uint64_t out = 0;
    for(int i=0; i<8; ++i) {
        out |= ((uint64_t) p[7-i]) << (i*8);
    }
    
    return out;
}

uint64_t ntohll(uint64_t netll)
{
    return htonll(netll);
}

// Debug function that prints an hex dump of a buffer
void dump_hex(void *buff, size_t size)
{
    for(int i=0; i<size; ++i) {
        printf("%02x ", ((unsigned char *) buff)[i]);
    }
    printf("\n");
}

// Commands
struct net_addr {
    uint64_t services;
    unsigned char ip_addr[16]; // If IPv4, 10 bytes of zeros, 2 FF bytes followed by 4 bytes of the address
    uint16_t port;
};

struct version_cmd {
    int32_t version;
    uint64_t services;
    int64_t timestamp;
    struct net_addr addr_recv;
    struct net_addr addr_from;
    uint64_t nonce;
    char user_agent; // TODO For now 0 but should be a var_str
    int32_t start_height;
};

typedef struct serialized_buffer {
    unsigned char *data;
    unsigned char *next;
    size_t size;
} serialized_buffer;

void serialized_buffer_init(serialized_buffer *buf, size_t size)
{
    buf->data = malloc(size);
    buf->next = buf->data;
    buf->size = size;
}

void serialized_buffer_destroy(serialized_buffer *buf)
{
    free(buf->data);
}

void serealize_long(serialized_buffer *buf, uint32_t val)
{
    val = htonl(val);
    memcpy((uint32_t *) buf->next, &val, sizeof(uint32_t));
    buf->next += sizeof(uint32_t);
}

void serealize_long_long(serialized_buffer *buf, uint64_t val)
{
    val = htonll(val);
    memcpy((uint64_t *) buf->next, &val, sizeof(uint64_t));
    buf->next += sizeof(uint64_t);
}

int send_version_cmd(int sock)
{
    /*
    struct version_cmd cmd;
    cmd.version = PROTO_VERSION;
    cmd.services = 1024;
    cmd.timestamp = time(NULL);
    cmd.addr_recv.services = SUPPORTED_SERVICES;
    //cmd.addr_recv.ip_addr = //TODO;
    */
    
    serialized_buffer buf;
    serialized_buffer_init(&buf, 1000);
    
    serealize_long(&buf, PROTO_VERSION);
    serealize_long_long(&buf, 1024);
    serealize_long_long(&buf, time(NULL));
    
    // TODO send message
    dump_hex(buf.data, 1000);
    serialized_buffer_destroy(&buf);
    return 0;
}

int main(int argc, char **argv)
{
    int sock = 0;
    send_version_cmd(sock);
    

    /*
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
    
    close(sock);
    */
    return 0;
}
