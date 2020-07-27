#ifndef BITCOIN_DNS_H
#define BITCOIN_DNS_H

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"

/* ----------------------------- SOCKET ------------------------------*/

// TODO this should not be hardcoded
#define DEFAULT_GATEWAY "192.168.0.1"
#define DNS_PORT        53

typedef enum bitcoin_socket_type {
    BITCOIN_SOCKET_TCP,
    BITCOIN_SOCKET_UDP
} bitcoin_socket_type;

typedef struct bitcoin_socket {
    bitcoin_socket_type type;
    int                 id;
    char                ip[15];
    uint16_t            port;
    struct sockaddr_in  sockaddr;
    bool                ready;
} bitcoin_socket;

int bitcoin_socket_init(bitcoin_socket *sock);
int bitcoin_socket_destroy(bitcoin_socket *sock);
int bitcoin_socket_send(bitcoin_socket *sock, buffer *buf);
int bitcoin_socket_recv(bitcoin_socket *sock, buffer *buf);

/* --------------------------- DNS --------------------------------*/

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
};

struct dns_question {
    char     domain[255];
    uint16_t type;
    uint16_t class;
};

struct dns_answer {
    char     name[255];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_lenght;
    unsigned char *data;
};

typedef struct dns_message {
    struct dns_header   header;
    struct dns_question question;
    struct dns_answer   answer;
} dns_message;


typedef struct bitcoin_dns_A_record {
    char                    ip[15];
} bitcoin_dns_A_record;
int test_dns();

#endif
