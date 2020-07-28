#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "dns.h"
#include "crypto.h"
#include "debug.h"

int bitcoin_socket_init(bitcoin_socket *sock, bitcoin_socket_type type, char *ip, uint16_t port)
{
    // Init data
    sock->type = type;
    sock->id = 0;
    strncpy(sock->ip, ip, 15);
    sock->port = port;
    sock->ready = false;
    
    // Create socket
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
    
    // Connect
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
    if(sock->ready) {
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
        sendto(sock->id, buf->data, buf->size, 0, (struct sockaddr *) &sock->sockaddr, sizeof(sock->sockaddr));
        break;
    }
    return 0;
}

int bitcoin_socket_recv(bitcoin_socket *sock, buffer *buf)
{
    // TODO: Hack, remove, this is needed only for UDP sockets
    struct sockaddr_in res_sockaddr;
    unsigned int len;
    
    switch(sock->type) {
    case BITCOIN_SOCKET_TCP:
        // TODO
        break;
    case BITCOIN_SOCKET_UDP:
        recvfrom(sock->id, buf->data, buf->size, 0, (struct sockaddr *) &res_sockaddr, &len);
        break;
    }
    return 0;
}

static void dns_serialize_label(buffer *buf, char *domain)
{
    char *label;
    while((label = strtok(domain, ".")) != NULL) {
        size_t len = strlen(label);
        buffer_push_u8(buf, len);
        buffer_push_string(buf, label, len);
        // Required by strok so that it continues to work on the same string
        domain = NULL;
    }
    buffer_push_u8(buf, 0);
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
    dns_serialize_label(buf, mess->question.domain);
    buffer_push_u16(buf, htons(mess->question.type));
    buffer_push_u16(buf, htons(mess->question.dns_class));
}

int dns_get_records(char *domain)
{
    bitcoin_socket sock;
    if(bitcoin_socket_init(&sock, BITCOIN_SOCKET_UDP, DEFAULT_GATEWAY, DNS_PORT) != 0) {
        printf("Error connecting DNS socket\n");
        return -1;
    }
    
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
        .question.domain         = "",
        .question.type           = 1,
        .question.dns_class      = 1
    };
    strncpy(message.question.domain, domain, 255);
    
    
    // Send request
    buffer req;
    buffer_init(&req);
    
    dns_serialize(&req, &message);
    dump_hex(req.data, req.size);       // Debug
    bitcoin_socket_send(&sock, &req);
    
    // Receive response
    buffer res;
    buffer_init(&res);
    bitcoin_socket_recv(&sock, &res);
    dump_hex(res.data, res.size);       // Debug
    
    // Cleanup
    buffer_destroy(&req);
    buffer_destroy(&res);
    bitcoin_socket_destroy(&sock);
    return 0;
}

int test_dns()
{
    printf("test dns\n");
    dns_get_records("seed.tbtc.petertodd.org");
    return 0;
}
