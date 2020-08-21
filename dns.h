#ifndef BITCOIN_DNS_H
#define BITCOIN_DNS_H

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"

// TODO this should not be hardcoded
#define DEFAULT_GATEWAY     "192.168.0.1"
#define DNS_PORT            53
#define DNS_MESSAGE_MAXLEN  512

struct dns_header {
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
};

struct dns_question {
    char     domain[256];
    uint16_t type;
    uint16_t dns_class;
};

struct dns_answer {
    char     domain[256];
    uint16_t type;
    uint16_t dns_class;
    uint32_t ttl;
    uint16_t data_lenght;
    unsigned char *data;
};

typedef struct dns_message {
    struct dns_header   header;
    struct dns_question *questions;
    struct dns_answer   *answers;
    // TODO Autorities section
    // TODO additionals section
} dns_message;

typedef struct bitcoin_dns_A_record {
    char                    ip[15];
} bitcoin_dns_A_record;

int dns_get_records(char *domain);
int test_dns();

#endif
