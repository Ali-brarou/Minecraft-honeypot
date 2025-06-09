#ifndef HONEYPOT_H
#define HONEYPOT_H

#include "global.h"
#include "log.h"

//protocol types
typedef enum MC_state_e {
    STATE_HANDSHAKE             = 0, 
    STATE_STATUS,          
    STATE_LOGIN, 
    STATE_TRANSFER, 
} MC_state_t; 

/* https://minecraft.wiki/w/Java_Edition_protocol/Server_List_Ping */
typedef enum Status_packet_id_e {
    STATUS_C2S_STATUS_REQUEST   = 0x00,  
    STATUS_C2S_PING             = 0x01, 

    STATUS_S2C_STATUS_RESPONSE  = 0x00,  
    STATUS_S2C_PONG             = 0x01, 
} Status_packet_id_t; 

typedef enum Login_packet_id_e {
    LOGIN_C2S_START             = 0x00, 
    LOGIN_S2C_DISCONNECT        = 0x00, 
    LOGIN_S2C_SUCCESS, 
} Login_packet_id_s; 

//handshake struct will only save next_state for now
typedef struct MC_handshake_s
{
    MC_state_t next_state; 
} MC_handshake_t; 

#define PLAYER_NAME_SIZE 64 /* mc username max is 16 this is very generous :3 */ 

typedef struct Client_s {
    int fd;
    char ip[INET6_ADDRSTRLEN];
    MC_state_t con_state; 

    //will be filled during login state
    char player_name[PLAYER_NAME_SIZE]; 
} Client_t; 

int client_init(Client_t* client, int client_fd, struct sockaddr_storage addr); 
void* handle_client(void* client); 

#endif
