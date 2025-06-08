#include "honeypot.h"


int client_init(Client_t* client, int client_fd, struct sockaddr_storage client_addr)
{
    client->fd = client_fd; 

    /* the initial connection state is always a handshake */
    client->con_state = STATE_HANDSHAKE; 

    void* addr; 
    switch(client_addr.ss_family)
    {
        case AF_INET: 
        {
            struct sockaddr_in * ipv4_sockaddr = (struct sockaddr_in*)&client_addr; 
            addr = (void*)&ipv4_sockaddr->sin_addr; 
            break; 
        }
        case AF_INET6: 
        {
            struct sockaddr_in6 * ipv6_sockaddr = (struct sockaddr_in6*)&client_addr; 
            addr = (void*)&ipv6_sockaddr->sin6_addr; 
            break; 
        }
        default: 
            fprintf(stderr, "Unknown address family %d\n", client_addr.ss_family); 
            goto FAIL; 

    }
    if (!inet_ntop(client_addr.ss_family, addr, client->ip, sizeof client->ip))
    {
        perror("inet_ntop"); 
        goto FAIL; 
    }
    return 0; 
FAIL: 
    if (client->fd >= 0)
    {
        close(client->fd); 
    }
    client->fd = -1; 
    return -1; 
}

static void disconnect_client(Client_t* client, char* msg)
{
    printf("%s Disconnected: %s\n", client->ip, msg); 
    logger_handle_event(LOG_DISCONNECT, client->ip, msg); 
    if (client->fd >= 0)
    {
        close(client->fd); 
    }
    client->fd = -1; 
    pthread_exit(NULL); 
}

static uint8_t recv_byte(Client_t* client)
{
    uint8_t res; 
    if (recv(client->fd, &res, 1, MSG_WAITALL) != 1)
    {
        disconnect_client(client, "invalid recv packet length"); 
    }
    return res; 
}

#define CONTINUE_BIT 0x80
#define SEGMENT_BITS 0x7F

static uint32_t recv_varint(Client_t* client)
{
    uint32_t result = 0; 
    uint8_t curr_byte; 
    int position = 0; 
    while (1)
    {
        curr_byte = recv_byte(client) ; 
        result |= (curr_byte & SEGMENT_BITS) << position; 
        if ((curr_byte & CONTINUE_BIT) == 0) break; 
        position += 7; 
        if (position >= 32)
        {
            disconnect_client(client, "varint too big"); 
        }
    }
    return result; 
}
#define recv_size_prefix recv_varint

static void recv_n_bytes(Client_t* client, void* buff, ssize_t len)
{
    if (recv(client->fd, buff, len, MSG_WAITALL) != len) 
    {
        disconnect_client(client, "invalid recv packet length"); 
    }
}

/* returns size prefix of packet */ 
static uint32_t recv_packet(Client_t* client, void* buff, ssize_t len)
{
    uint32_t size_prefix = recv_size_prefix(client); 
    if (size_prefix >= len || size_prefix == 0)
    {
        disconnect_client(client, "invalid size prefix"); 
    }
        
    recv_n_bytes(client, buff, size_prefix); 
    return size_prefix; 
}

static void send_byte(Client_t* client, uint8_t val)
{
    send(client->fd, &val, 1, 0); 
}

static void send_n_bytes(Client_t* client, void* buff, size_t len)
{
    send(client->fd, buff, len, 0); 
}

static void send_varint(Client_t* client, uint32_t val)
{
    while (1)
    {
        if ((val & ~SEGMENT_BITS) == 0) 
        {
            send_byte(client, val); 
            return; 
        }
        send_byte(client, (val & SEGMENT_BITS) | CONTINUE_BIT); 
        val >>= 7; 
    }
}
#define send_size_prefix send_varint

/* returns how many bytes are written into the buffer or -1 if it can't */
static ssize_t pack_varint(uint8_t* target, size_t len, uint32_t val)
{
    size_t i = 0; 
    for (;i < len; i++)
    {
        if ((val & ~SEGMENT_BITS) == 0) 
        {
            target[i] = (uint8_t)val; 
            return ++i; 
        }

        target[i] = ((uint8_t)val & SEGMENT_BITS) | CONTINUE_BIT; 
        val >>= 7; 
    }
    return -1; 
}

/* returns how many bytes are used for the varint or -1 if it can't parse */ 
static ssize_t parse_varint(uint8_t* buff, size_t len, uint32_t* target_val)
{
    size_t i = 0; 
    int position = 0; 
    uint32_t result = 0; 
    *target_val = 0; 
    for (;i < len; i++)
    {
        result |= (buff[i] & SEGMENT_BITS) << position; 
        if ((buff[i] & CONTINUE_BIT) == 0)
        {
            *target_val = result;  
            return ++i; 
        }
        position += 7; 
        if (position >= 32)
        {
            return -1; 
        }
    }
    return -1; 
}

static void parse_handshake(uint8_t* buff, size_t len, MC_handshake_t* handshake)
{
    //next state is just the last byte for now
    handshake->next_state = buff[len-1]; 
}

#define LEGACY_PING_ID 0xFE

void handle_client_handshake(Client_t* client)
{
    uint8_t handshake_buffer[BUFFER_SIZE]; 
    MC_handshake_t handshake; 

    uint32_t size_prefix = recv_size_prefix(client); 
    if (size_prefix >= sizeof handshake_buffer || size_prefix == 0)
    {
        disconnect_client(client, "invalid size prefix"); 
    }

    if (size_prefix == LEGACY_PING_ID)
    {
        disconnect_client(client, "legacy ping is not implemented"); 
    }
    recv_n_bytes(client, handshake_buffer, size_prefix); 
    parse_handshake(handshake_buffer, size_prefix, &handshake); 

    client->con_state = handshake.next_state; 
}

static void send_fake_status(Client_t* client)
{
    size_t fstat_size = strlen(FAKE_STATUS);

    /* fist store the packet into a buffer, calculate size then send it */
    char* buffer = malloc(fstat_size + 6); 
    if (!buffer)
    {
        perror("malloc"); 
        disconnect_client(client, "unable to allocate memory"); 
    }
    buffer[0] = STATUS_S2C_STATUS_RESPONSE;                         /* packet id */ 
    ssize_t i = pack_varint((uint8_t*)&buffer[1], 4, fstat_size);   /* response size */
    if (i == -1)
    {
        free(buffer); 
        disconnect_client(client, "unable to pack varint"); 
    }
    memcpy(&buffer[i+1], FAKE_STATUS, fstat_size);                  /* response */ 

    /* sending size of the packet */ 
    send_size_prefix(client, fstat_size+1+i); 
    
    send_n_bytes(client, buffer, fstat_size+1+i); 
    free(buffer); 
}

#define PING_PACKET_SIZE 9

void handle_client_status(Client_t* client)
{
    uint32_t size_prefix = recv_size_prefix(client); 
    if (size_prefix != 1)
    {
        disconnect_client(client, "invalid status packet prefix size"); 
    }
    uint8_t packet_id = recv_byte(client); 
    if (packet_id != STATUS_C2S_STATUS_REQUEST)
    {
        disconnect_client(client, "invalid status packet id"); 
    }
    send_fake_status(client); 

    /* recv ping */ 
    size_prefix = recv_size_prefix(client); 
    if (size_prefix != PING_PACKET_SIZE)
    {
        disconnect_client(client, "invalid ping packet size"); 
    }

    packet_id = recv_byte(client); 
    if (packet_id != STATUS_C2S_PING)
    {
        disconnect_client(client, "invalid ping packet id"); 
    }
    char payload[PING_PACKET_SIZE - 1]; 
    recv_n_bytes(client, payload, PING_PACKET_SIZE - 1); 
    
    /* send pong */ 
    send_size_prefix(client, PING_PACKET_SIZE);         /* packet size */
    send_byte(client, STATUS_S2C_PONG);                 /* packet id   */ 
    send_n_bytes(client, payload, PING_PACKET_SIZE-1);  /* payload     */ 
    disconnect_client(client, "finishied status connection"); 
}

void handle_client_login(Client_t* client)
{
    /* login start */ 
    uint8_t buffer[BUFFER_SIZE]; 
    uint32_t size_prefix = recv_packet(client, buffer, sizeof buffer); 
    (void)size_prefix; 
    if (buffer[0] != LOGIN_C2S_START)
    {
        disconnect_client(client, "invalid login start id"); 
    }
    uint32_t string_size; 
    ssize_t i = parse_varint(&buffer[1], size_prefix - 1, &string_size); 
    if (i == -1)
    {
        disconnect_client(client, "bad name string size"); 
    }
    if (i+1+string_size >= size_prefix || string_size+1 >= sizeof client->player_name)
    {
        disconnect_client(client, "very long player name"); 
    }
    memcpy(client->player_name, &buffer[1+i], string_size); 
    client->player_name[string_size] = '\0'; 
    printf("%s: A player trying to login : %s\n", client->ip, client->player_name); 
    logger_handle_event(LOG_LOGIN, client->ip, client->player_name); 
    disconnect_client(client, "not fully implemented login state"); 
}

void* handle_client(void* arg)
{
    Client_t client = *(Client_t*)arg; 
    free(arg); 

    printf("Connection from ip : %s\n", client.ip); 
    logger_handle_event(LOG_CONNECT, client.ip, NULL); 

    while(1)
    {
        switch (client.con_state)
        {
            case STATE_HANDSHAKE: 
                handle_client_handshake(&client); 
                break; 
            case STATE_STATUS: 
                printf("%s requested status\n", client.ip); 
                logger_handle_event(LOG_FETCH_STATUS, client.ip, NULL); 
                handle_client_status(&client); 
                break; 
            case STATE_LOGIN:
                handle_client_login(&client); 
                break; 
            default: 
                disconnect_client(&client, "not implemented connection state"); 
                return NULL; 
        }
    }
    return NULL; 
}
