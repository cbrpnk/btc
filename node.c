#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "proto.h"
#include "node.h"
#include "crypto.h"
#include "debug.h"
#include "network.h"

int bc_node_connect(bc_node *remote)
{
    if((remote->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        printf("Socket creation error\n");
        return -1;
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(remote->port);
    memcpy(&server_addr.sin_addr, &remote->ip, sizeof(remote->ip));
    
    if((connect(remote->socket, (struct sockaddr *) &server_addr,
            sizeof(server_addr))) < 0) {
        printf("Connection Failed\n");
        return -1;
    }
    
    remote->connected = true;
    return 0;
}

int bc_node_disconnect(bc_node *remote)
{
    close(remote->socket);
    return 0;
}

void bc_node_handshake(bc_node *node)
{
    bc_msg_version msg = {
        .version = node->protocol_version,
        .services = 1,
        .timestamp = (uint64_t) time(NULL),
        .dest = {
            .time = 0,
            .services = 1,
            .ip = (uint64_t) node->ip,
            .port = node->port
        },
        .src = {
            .time = 0,
            .services = 1,
            .ip = 0,
            .port = 0
        },
        .nonce = gen_nonce_64(),
        .user_agent = "/test:0.0.1/",
        .start_height = 0,
        .relay = 1
    };
    
    send_version(node, &msg);
    
    
    printf("RECV-------------------------------------------\n");
    unsigned char message_buffer[2000] = {0};
    // TODO Custom recv that gets a full message
    int len = recv(node->socket, message_buffer, 2000, 0);
    dump_hex(message_buffer, len);
    printf("END-------------------------------------------\n");
}
