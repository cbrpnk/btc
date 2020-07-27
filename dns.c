#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "dns.h"
#include "crypto.h"
#include "debug.h"


int bitcoin_socket_init(bitcoin_socket *sock)
{
    switch(sock->type) {
    case BITCOIN_SOCKET_TCP:
        sock->id = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        break;
    case BITCOIN_SOCKET_UDP:
        sock->id = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        break;
    default:
        printf("Invalid bitcoin_socket_type\n");
        return -1;
    }
    if(sock->id < 0) {
        printf("Socket creation error\n");
        return -1;
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(sock->port);
    inet_pton(AF_INET, sock->ip, &server_addr.sin_addr);
    
    switch(sock->type) {
    case BITCOIN_SOCKET_TCP:
        if((connect(sock->id, (struct sockaddr *) &server_addr,
                sizeof(server_addr))) < 0) {
            printf("Connection Failed\n");
            return -1;
        }
        break;
    case BITCOIN_SOCKET_UDP:
        sock->sockaddr = server_addr;
        break;
    }
        
    sock->ready = true;
    return 0;
}

int bitcoin_socket_destroy(bitcoin_socket *sock)
{
    if(sock->type == BITCOIN_SOCKET_TCP  && sock->ready) {
        close(sock->id);
    }
    sock->ready = false;
    return 0;
}

int bitcoin_socket_send(bitcoin_socket *sock, buffer *buf)
{
    return 0;
}

int bitcoin_socket_recv(bitcoin_socket *sock, buffer *buf)
{
    return 0;
}

uint16_t dns_gen_flags(bool qr, uint8_t opcode, bool aa, bool tc, bool rd,
                       bool ra, uint8_t rcode)
{
    uint16_t flags = 0;
    flags |= qr;
    flags |= (opcode & 0x0f) << 1;
    flags |= aa << 5;
    flags |= tc << 6;
    flags |= rd << 7;
    flags |= ra << 8;
    flags |= rcode << 12;
    
    return flags;
}

int dns_get_records(bitcoin_socket *sock, char *domain)
{
    // Create request
    dns_message message = {
        .header.id = gen_nonce_16(),
        .header.flags = dns_gen_flags(0, 0, 0, 0, 1, 0, 0),
    };
    
    dump_hex(&message, 32);
    
    // Serialize request
    buffer req;
    buffer_init(&req);
    
    // Send / Recv
    bitcoin_socket_send(sock, &req);
    
    // Deserialize response
    
    buffer_destroy(&req);
    return 0;
}

int test_dns()
{
    printf("test dns\n");
    
    bitcoin_socket dns_socket = {
        .type = BITCOIN_SOCKET_UDP,
        .id = 0,
        .ip = DEFAULT_GATEWAY,
        .port = DNS_PORT,
        .ready = false
    };
    
    if(bitcoin_socket_init(&dns_socket) != 0) {
        printf("Error connecting DNS socket\n");
        return -1;
    }
    
    dns_get_records(&dns_socket, "seed.tbtc.petertodd.org");
    
    bitcoin_socket_destroy(&dns_socket);
    return 0;
}
