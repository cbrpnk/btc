#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

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
    switch(sock->type) {
    case BITCOIN_SOCKET_TCP:
        // TODO
        break;
    case BITCOIN_SOCKET_UDP:
        sendto(sock->id, buf->data, buf->size, 0, &(sock->sockaddr), sizeof(sock->sockaddr));
        break;
    }
    return 0;
}

int bitcoin_socket_recv(bitcoin_socket *sock, buffer *buf)
{
    return 0;
}

void dns_serialize(buffer *buf, dns_message *mess)
{
    // Id
    buffer_push_u16(buf, mess->header.id);
    // Flags
    uint16_t flags = 0;
    flags |= mess->header.qr;
    flags |= (mess->header.opcode & 0x0f) << 1;
    flags |= mess->header.aa << 5;
    flags |= mess->header.tc << 6;
    flags |= mess->header.rd << 7;
    flags |= mess->header.ra << 8;
    flags |= mess->header.rcode << 12;
    buffer_push_u16(buf, htons(flags));
    // section count
    buffer_push_u16(buf, htons(mess->header.question_count));
    buffer_push_u16(buf, htons(mess->header.answer_count));
    buffer_push_u16(buf, htons(mess->header.authority_count));
    buffer_push_u16(buf, htons(mess->header.additional_count));
    // Question section

    // TODO !!!!
    buffer_push_u8(buf, 6); // ?????
    buffer_push_string(buf, "google", strlen("google"));
    buffer_push_u8(buf, 3); // ?????
    buffer_push_string(buf, "com", strlen("com"));
    buffer_push_u8(buf, 0); // ?????
    // End TODO
    buffer_push_u16(buf, htons(mess->question.type));
    buffer_push_u16(buf, htons(mess->question.dns_class));
}

int dns_get_records(bitcoin_socket *sock, char *domain)
{
    // Create request
    dns_message message = {
        .header.id               = gen_nonce_16(),
        .header.qr               = 0,
        .header.opcode           = 0,
        .header.aa               = 0,
        .header.tc               = 0,
        .header.rd               = 1,
        .header.ra               = 0,
        .header.rcode            = 0,
        .header.question_count   = 1,
        .header.answer_count     = 0,
        .header.authority_count  = 0,
        .header.additional_count = 0,
        .question.domain         = "google.com",
        .question.type           = 1,
        .question.dns_class      = 1
    };
    
    
    // Serialize request
    buffer req;
    buffer_init(&req);
    
    dns_serialize(&req, &message);
    dump_hex(req.data, req.size);
    
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
