#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "dns.h"
#include "crypto.h"
#include "debug.h"

static void create_message(dns_message *mess, bool qr, uint8_t opcode, bool aa, bool tc, bool rd, bool ra,
                           uint8_t rcode)
{
    mess->header.id = gen_nonce_16();
    mess->header.qr = qr;
    mess->header.opcode = opcode;
    mess->header.aa = aa;
    mess->header.tc = tc;
    mess->header.rd = rd;
    mess->header.ra = ra;
    mess->header.rcode = rcode;
    mess->header.question_count = 0;
    mess->header.answer_count = 0;
    mess->header.authority_count = 0;
    mess->header.additional_count = 0;
    
    mess->questions = NULL;
    mess->answers = NULL;
}

static void destroy_message(dns_message *mess)
{
    free(mess->questions);
    free(mess->answers);
}

static void add_question(dns_message *mess, char *domain, uint16_t type, uint16_t dns_class)
{
    //printf("%d aaaa\n", mess->header.question_count);
    mess->questions = realloc(mess->questions, sizeof(struct dns_question));
    uint16_t *id = &mess->header.question_count;
    strncpy(mess->questions[*id].domain, domain, 256); // TODO Remove magic number
    printf("%s\n", domain);
    mess->questions[*id].type = type;
    mess->questions[*id].dns_class = dns_class;
    (*id)++;
}


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

static void dns_deserialize_label(buffer *buf, char *domain)
{
    // Check wether record's label is in the compressed format.
    // Compressed format starts with 11 as the MSBs
    if(*(buf->data+buf->next) >= 0xc0) {
        printf("%d\n", buf->next);
        // Compressed
        uint16_t offset = buffer_pop_u16(buf);
        //offset &= 0x3;
        //printf("%d\n", offset);
    } else {
        // Not compressed
        uint8_t len = 0;
        int i=0;
        while((len = buffer_pop_u8(buf)) != 0) {
            if(i>0) {
                domain[i++] = '.';
            }
            for(int j=0; j<len; ++j) {
                domain[i++] = buffer_pop_u8(buf);
            }
        }
    }
}

static void dns_serialize(buffer *buf, dns_message *mess)
{
    // Id
    buffer_push_u16(buf, htons(mess->header.id));
    // Flags
    dns_serialize_flags(buf, mess);
    // Section count
    buffer_push_u16(buf, htons(mess->header.question_count));
    buffer_push_u16(buf, htons(mess->header.answer_count));
    buffer_push_u16(buf, htons(mess->header.authority_count));
    buffer_push_u16(buf, htons(mess->header.additional_count));
    
    // Question section
    for(int i=0; i<mess->header.question_count; ++i) {
        struct dns_question *q = mess->questions+i;
        dns_serialize_label(buf, q->domain);
        buffer_push_u16(buf, htons(q->type));
        buffer_push_u16(buf, htons(q->dns_class));
    }
}

static void dns_deserialize(dns_message *mess, buffer *buf)
{
    // TODO here create message using new method
    create_message(mess, 0, 0, 0, 0, 0, 0, 0);
    
    // Id
    mess->header.id = ntohs(buffer_pop_u16(buf));
    // Flags
    dns_deserialize_flags(mess, buf);
    
    // We do not fill the "count" section of the header but rather 
    // let the following add_(question/answer...)() function calls do that 
    // for us.
    uint16_t question_count = ntohs(buffer_pop_u16(buf));
    uint16_t answer_count = ntohs(buffer_pop_u16(buf));
    uint16_t authority_count = ntohs(buffer_pop_u16(buf));
    uint16_t additional_count = ntohs(buffer_pop_u16(buf));
    
    // Questions section
    for(int i=0; i<question_count; ++i) {
        struct dns_question q;
        dns_deserialize_label(buf, q.domain);
        q.type = ntohs(buffer_pop_u16(buf));
        q.dns_class = ntohs(buffer_pop_u16(buf));
        add_question(mess, q.domain, q.type, q.dns_class);
    }
    
    // Answers section
    for(int i=0; i<answer_count; ++i) {
        struct dns_answer a;
        dns_deserialize_label(buf, a.domain);
    }
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

static void send_request(int sock, struct sockaddr_in *server_addr,
                         dns_message *mess)
{
    // Send request
    buffer req;
    buffer_init(&req, DNS_MESSAGE_MAXLEN);
    dns_serialize(&req, mess);
    sendto(sock, req.data, req.size, 0, (struct sockaddr *) server_addr,
           sizeof(*server_addr));
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
    dns_message request;
    create_message(&request, 0, 0, 0, 0, 1, 0, 0);
    add_question(&request, domain, 1, 1);
    send_request(sock, &server_addr, &request);
    destroy_message(&request);
    
    // Response
    dns_message response;
    recv_response(sock, &response);
    destroy_message(&response);
    //printf("id: %x\n", response.header.id);
    //rintf("answer count: %d\n", response.header.answer_count);
    
    close(sock);
    return 0;
}
