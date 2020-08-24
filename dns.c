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
#include "serial_buffer.h"

////////////////////////////////////////// Message ////////////////////////////////////////////////

static void message_init(struct dns_message *mess, bool qr, uint8_t opcode, bool aa, bool tc, bool rd, bool ra,
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

static void message_destroy(struct dns_message *mess)
{
    for(int i=0; i<mess->header.question_count; ++i) {
        free(mess->questions[i].domain);
    }
    free(mess->questions);
    
    for(int i=0; i<mess->header.answer_count; ++i) {
        free(mess->answers[i].domain);
        free(mess->answers[i].data);
    }
    free(mess->answers);
}

static dns_question *add_question(struct dns_message *mess, char *domain, dns_record_type type,
                                  uint16_t dns_class)
{
    uint16_t *question_count = &mess->header.question_count;
    mess->questions = realloc(mess->questions, sizeof(struct dns_question) 
                              * (*question_count+1));
    dns_question *q = &mess->questions[*question_count];
    if(domain != NULL) {
        q->domain = malloc(strlen(domain) + 1);
        strcpy(q->domain, domain);
    } else {
        q->domain = NULL;
    }
    q->type = type;
    q->dns_class = dns_class;
    
    (*question_count)++;
    return q;
}

/*
static dns_answer *add_answer(struct dns_message *mess)
{
    // TODO
    return NULL;
}
*/

/////////////////////////////////// Serialization / Deserialization //////////////////////////////////////

static void dns_serialize_flags(serial_buffer *buf, struct dns_message *mess)
{
    uint16_t flags = 0;
    
    flags |= mess->header.qr << 15;
    flags |= (mess->header.opcode & 0x0f) << 11;
    flags |= mess->header.aa << 10;
    flags |= mess->header.tc << 9;
    flags |= mess->header.rd << 8;
    flags |= mess->header.ra << 7;
    flags |= (mess->header.rcode & 0x0f);
    
    serial_buffer_push_u16(buf, htons(flags));
    
}

static void dns_deserialize_flags(struct dns_message *mess, serial_buffer *buf)
{
    uint16_t flags = ntohs(serial_buffer_pop_u16(buf));
    mess->header.qr = flags >> 15;
    mess->header.opcode = (flags >> 11) & 0x0f;
    mess->header.aa = (flags >> 10) & 1;
    mess->header.tc = (flags >> 9) & 1;
    mess->header.rd = (flags >> 8) & 1;
    mess->header.ra = (flags >> 7) & 1;
    mess->header.rcode = flags & 0x0f;
}

static void dns_serialize_label(serial_buffer *buf, char *domain)
{
    char *label;
    while((label = strtok(domain, ".")) != NULL) {
        size_t len = strlen(label);
        serial_buffer_push_u8(buf, len);
        serial_buffer_push_mem(buf, label, len);
        // Required by strok so that it continues to work on the same string
        domain = NULL;
    }
    // Zero-terminated string
    serial_buffer_push_u8(buf, 0);
}

static int read_label(char *domain, uint8_t *data) {
    uint8_t len = 0;
    int i=0;
    while(true) {
        len = data[i++];
        if(len == 0) break;
        
        if(i>1) {
            *domain++ = '.';
        }
        
        for(int j=0; j<len; ++j) {
            *domain++ = data[i++];
        }
    }
    *domain++ = '\0';
    
    return i;
}

static void dns_deserialize_label(serial_buffer *buf, char *domain)
{
    // Check wether record's label is in the compressed format.
    // Compressed format starts with 11 as the MSBs
    if(*(buf->data+buf->next) >= 0xc0) {
        // Compressed
        uint16_t offset = ntohs(serial_buffer_pop_u16(buf));
        offset &= 0x3fff;
        read_label(domain, buf->data+offset);
    } else {
        // Not compressed
        buf->next += read_label(domain, buf->data+buf->next);
    }
}

static void dns_serialize(serial_buffer *buf, struct dns_message *mess)
{
    // Id
    serial_buffer_push_u16(buf, htons(mess->header.id));
    // Flags
    dns_serialize_flags(buf, mess);
    // Section count
    serial_buffer_push_u16(buf, htons(mess->header.question_count));
    serial_buffer_push_u16(buf, htons(mess->header.answer_count));
    serial_buffer_push_u16(buf, htons(mess->header.authority_count));
    serial_buffer_push_u16(buf, htons(mess->header.additional_count));
    
    // Question section
    for(int i=0; i<mess->header.question_count; ++i) {
        struct dns_question *q = mess->questions+i;
        dns_serialize_label(buf, q->domain);
        serial_buffer_push_u16(buf, htons(q->type));
        serial_buffer_push_u16(buf, htons(q->dns_class));
    }
}

static void dns_deserialize(struct dns_message *mess, serial_buffer *buf)
{
    message_init(mess, 0, 0, 0, 0, 0, 0, 0);
    
    // Id
    mess->header.id = ntohs(serial_buffer_pop_u16(buf));
    // Flags
    dns_deserialize_flags(mess, buf);
    
    uint16_t question_count = ntohs(serial_buffer_pop_u16(buf));
    uint16_t answer_count = ntohs(serial_buffer_pop_u16(buf));
    mess->header.authority_count = ntohs(serial_buffer_pop_u16(buf));
    mess->header.additional_count = ntohs(serial_buffer_pop_u16(buf));
    
    // Questions section
    mess->questions = malloc(sizeof(struct dns_question) * mess->header.question_count);
    for(int i=0; i<question_count; ++i) {
        // TODO Add_question is buggy
        dns_question *q = add_question(mess, NULL, DNS_TYPE_NULL, 0);
        char label[256] = {0};
        dns_deserialize_label(buf, label);
        q->domain = realloc(q->domain, strlen(label)+1);
        strcpy(q->domain, label);
        q->type = ntohs(serial_buffer_pop_u16(buf));
        q->dns_class = ntohs(serial_buffer_pop_u16(buf));
    }
    
    // Answers section
    mess->answers = malloc(sizeof(struct dns_answer) * mess->header.answer_count);
    for(int i=0; i<answer_count; ++i) {
        struct dns_answer *a = mess->answers+i;
        char label[256] = {0};
        dns_deserialize_label(buf, label);
        a->domain = malloc(strlen(label)+1);
        strcpy(a->domain, label);
        a->type = ntohs(serial_buffer_pop_u16(buf));
        a->dns_class = ntohs(serial_buffer_pop_u16(buf));
        a->ttl = ntohl(serial_buffer_pop_u32(buf));
        a->len = ntohs(serial_buffer_pop_u16(buf));
        a->data = malloc(a->len);
        serial_buffer_pop_mem(a->data, a->len, buf);
    }
}

////////////////////////////// Network ///////////////////////////////////////////////

static int create_socket(int *sock, struct sockaddr_in *server_addr)
{
    *sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    // Settings
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, DEFAULT_GATEWAY, &server_addr->sin_addr);
    
    return 0;
}

static void send_request(int sock, struct sockaddr_in *server_addr,
                         struct dns_message *mess)
{
    // Send request
    serial_buffer req;
    serial_buffer_init(&req, DNS_MESSAGE_MAXLEN);
    dns_serialize(&req, mess);
    sendto(sock, req.data, req.size, 0, (struct sockaddr *) server_addr,
           sizeof(*server_addr));
    serial_buffer_destroy(&req);
}

static void recv_response(int sock, struct dns_message *mess)
{
    // Receive response
    serial_buffer res;
    serial_buffer_init(&res, DNS_MESSAGE_MAXLEN);
    int read_len = recvfrom(sock, res.data, 512, 0, NULL, NULL);
    res.size += read_len;
    dns_deserialize(mess, &res);
    // TODO Check if the nonce matches our request
    serial_buffer_destroy(&res);
}

///////////////////////////////////// API /////////////////////////////////////

int dns_query(dns_message *req, dns_message *res)
{
    int sock = 0;
    struct sockaddr_in server_addr;
    
    if(create_socket(&sock, &server_addr) != 0) {
        return -1;
    }
    
    send_request(sock, &server_addr, req);
    recv_response(sock, res);
    
    close(sock);
    return 0;
}

int dns_get_records(char *domain, dns_record_type type, struct dns_message *response)
{
    dns_message request;
    message_init(&request, 0, 0, 0, 0, 1, 0, 0);
    add_question(&request, domain, type, 1);
    
    dns_query(&request, response);
    message_destroy(&request);
    return 0;
}

int dns_get_records_a(char *domain, dns_record_a *rec)
{
    struct dns_message response;
    dns_get_records(domain, DNS_TYPE_A, &response);
    rec->ttl = response.answers[0].ttl;
    rec->ip = *((uint32_t *) response.answers[0].data);
    message_destroy(&response);
    return 0;
}
