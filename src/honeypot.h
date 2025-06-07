#ifndef HONEYPOT_H
#define HONEYPOT_H

#include "global.h"
#include "log.h"

//protocol types
typedef enum MC_state_e {
    STATE_HANDSHAKE = 0, 
    STATE_STATUS,          
    STATE_LOGIN, 
    STATE_TRANSFER, 
} MC_state_t; 

//handshake struct will only save next_state for now
typedef struct MC_handshake_s
{
    MC_state_t next_state; 
} MC_handshake_t; 

typedef struct Client_s {
    int fd;
    char ip[INET6_ADDRSTRLEN];
    MC_state_t con_state; 
} Client_t; 

int client_init(Client_t* client, int client_fd, struct sockaddr_storage addr); 
void* handle_client(void* client); 

#endif
