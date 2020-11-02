#ifndef BITCOIN_DNS_H
#define BITCOIN_DNS_H

#include <stdint.h>
#include <stdbool.h>

// TODO this should not be hardcoded
#define DNS_SERVER_IP       0x01010101 //"1.1.1.1"
#define DNS_SERVER_PORT     53
#define DNS_MESSAGE_MAXLEN  512

typedef enum dns_record_type {
    DNS_TYPE_NULL  = 0,
    DNS_TYPE_A     = 1,
    DNS_TYPE_NS    = 2,
    DNS_TYPE_CNAME = 5,
    DNS_TYPE_MX    = 15,
    DNS_TYPE_TXT   = 16,
    DNS_TYPE_AAAA  = 28,
} dns_record_type;

typedef struct dns_header {
    // A random nonce used to match answers with questions
    uint16_t id;
    // Flags
    bool     qr;                    // Query 0, Response 1
    uint8_t  opcode;
    bool     aa;
    bool     tc;
    bool     rd;
    bool     ra;
    uint8_t  rcode;
    // Section count
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
} dns_header;

typedef struct dns_question {
    char     *domain;       // Null terminated
    uint16_t type;
    uint16_t dns_class;
} dns_question;

typedef struct dns_answer {
    char     *domain;       // Null terminated
    uint16_t type;
    uint16_t dns_class;
    uint32_t ttl;
    uint16_t len;
    uint8_t  *data;
} dns_answer;

typedef struct dns_message {
    struct dns_header    header;
    struct dns_question *questions;
    struct dns_answer   *answers;
    // TODO Autorities section (not implemented)
    // TODO additionals section (not implemented)
} dns_message;

typedef struct dns_record_a {
    uint32_t ttl;
    uint32_t ip;
} dns_record_a;

int dns_query(dns_message *req, dns_message *res);
int dns_get_records(char *domain, dns_record_type type, struct dns_message *response);
int dns_get_records_a(char *domain, dns_record_a *rec);

#endif
