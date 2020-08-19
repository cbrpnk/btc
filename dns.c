#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "dns.h"
#include "crypto.h"
#include "debug.h"

static void dns_serialize_flags(buffer *buf, dns_message *mess)
{
    uint16_t flags = 0;
    
    flags |= mess->header.qr << 15;
    flags |= (mess->header.opcode & 0x0f) << 11;
    flags |= mess->header.aa << 10;
    flags |= mess->header.tc << 9;
    flags |= mess->header.rd << 8;
    flags |= mess->header.ra << 7;
    flags |= (mess->header.rcode & 0x0f);
    
    buffer_push_u16(buf, htons(flags));
    
}

static void dns_deserialize_flags(dns_message *mess, buffer *buf)
{
    uint16_t flags = ntohs(buffer_pop_u16(buf));
    mess->header.qr = flags >> 15;
    mess->header.opcode = (flags >> 11) & 0x0f;
    mess->header.aa = (flags >> 10) & 1;
    mess->header.tc = (flags >> 9) & 1;
    mess->header.rd = (flags >> 8) & 1;
    mess->header.ra = (flags >> 7) & 1;
    mess->header.rcode = flags & 0x0f;
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

static void dns_serialize(buffer *buf, dns_message *mess)
{
    // Id
    buffer_push_u16(buf, htons(mess->header.id));
    // Flags
    dns_serialize_flags(buf, mess);
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

static void dns_deserialize(dns_message *mess, buffer *buf)
{
    mess->header.id = ntohs(buffer_pop_u16(buf));
    dns_deserialize_flags(mess, buf);
}

static int create_socket(int *sock, struct sockaddr_in *server_addr)
{
    *sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    // Settings
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, DEFAULT_GATEWAY, &server_addr->sin_addr);
    
    // Connect
    if((connect(*sock, (struct sockaddr *) server_addr,
            sizeof(*server_addr))) < 0) {
        printf("Connection Failed\n");
        return -1;
    }
    
    return 0;
}

static void send_request(int sock, struct sockaddr_in *server_addr, dns_message *mess)
{
    // Send request
    buffer req;
    buffer_init(&req, DNS_MESSAGE_MAXLEN);
    dns_serialize(&req, mess);
    sendto(sock, req.data, req.size, 0, (struct sockaddr *) server_addr, sizeof(*server_addr));
    buffer_destroy(&req);
}

static void recv_response(int sock, dns_message *mess)
{
    // Receive response
    buffer res;
    buffer_init(&res, DNS_MESSAGE_MAXLEN);
    int read_len = recvfrom(sock, res.data, 512, 0, NULL, NULL);
    res.size += read_len;
    dump_hex(res.data, res.size);
    dns_deserialize(mess, &res);
    buffer_destroy(&res);
}

int dns_get_records(char *domain)
{
    int sock = 0;
    struct sockaddr_in server_addr;
    
    if(create_socket(&sock, &server_addr) != 0) {
        return -1;
    }
    
    // Request
    dns_message message = {0};
    message.header.id = gen_nonce_16();
    message.header.rd = 1;
    message.header.question_count = 1;
    strncpy(message.question.domain, domain, 255);
    message.question.type = 1;
    message.question.dns_class = 1;
    send_request(sock, &server_addr, &message);
    
    // Response
    dns_message response = {0};
    recv_response(sock, &response);
    printf("id: %x\n", response.header.id);
    printf("answer count: %d\n", response.header.answer_count);
    
    close(sock);
    return 0;
}
