#include "server.h"

volatile sig_atomic_t server_running = 1;
atomic_int current_clients = 0;

void server_handle_sigint(int sig)
{
    (void)sig; 
    server_running = 0;  
}

/*after little research I find a way to make SIGINT interrupt accept by making it non blocking*/  
static int make_socket_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    /* add the noblock flag */ 
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(O_NONBLOCK)");
        return -1; 
    }
    return 0; 
}

int setup_server(void)
{
    struct addrinfo hints, *res, *p; 
    int status; 
    int listen_fd = -1; 
    int yes = 1; 

    memset(&hints, 0, sizeof hints); 
    hints.ai_family = AF_UNSPEC; /* for both ipv4 and ipv6 */
    hints.ai_socktype = SOCK_STREAM; /* tcp server */
    hints.ai_flags = AI_PASSIVE;
    
    if ((status = getaddrinfo(NULL, PORT, &hints, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status)); 
        return -1; 
    }
    
    for (p = res; p != NULL; p = p -> ai_next)
    {
        listen_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listen_fd == -1)
        {
            perror("socket"); 
            goto fail; 
        }

        if (setsockopt(listen_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) == -1) 
        {
            perror("setsockopt"); 
            goto fail; 
        }

        if (bind(listen_fd, p->ai_addr, p->ai_addrlen) == -1)
        {
            perror("bind"); 
            goto fail; 
        }
        break;  
fail: 
        if (listen_fd != -1)
            close(listen_fd); 
        listen_fd = -1; 
        continue; 
    }

    if (listen_fd == -1)
    {
        fprintf(stderr, "Creating socket failed\n"); 
        return -1; 
    }
    
    freeaddrinfo(res); 

    if (listen(listen_fd, BACKLOG) == -1)
    {
        perror("listen"); 
        close(listen_fd);
        return -1; 
    }

    if (make_socket_nonblocking(listen_fd) != 0)
        return -1; 

    return listen_fd; 
}

static void set_socket_timeout(int fd, int timeout_sec) {
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
        perror("setsockopt");
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
        perror("setsockopt");
    }
}

void accept_loop(int listen_fd)
{
    struct sockaddr_storage client_addr; 
    socklen_t addr_size; 
    int client_fd = -1; 
    
    while (server_running)
    {
        pthread_t thread_id; 
        addr_size = sizeof client_addr; 

        client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_size); 
        if (client_fd == -1)
        {
            if (errno == EINTR)
                continue; 
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* I was having issues with 100% cpu and the solution was to sleep lil bit thanks chatgpt */ 
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
                nanosleep(&ts, NULL);
                continue;
            }
            perror("accept"); 
            break; 
        }
        /* add timeout to recv and send operations duh */
        set_socket_timeout(client_fd, CLIENT_TIMEOUT_SEC);


        Client_t* client = malloc(sizeof(Client_t)); 
        if (client == NULL)
        {
            perror("malloc"); 
            close(client_fd); 
            continue; 
        }
        if (client_init(client, client_fd, client_addr) != 0)
        {
            fprintf(stderr, "failed to initlized client\n"); 
            free(client); 
            close(client_fd); 
            continue; 
        }

        //log connection
        logger_handle_event(LOG_CONNECT, client->ip, NULL);

        if (atomic_fetch_add(&current_clients, 1) >= MAX_CLIENTS) {
            atomic_fetch_sub(&current_clients, 1);
            fprintf(stderr, "Too many clients. Rejecting connection.\n");
            logger_handle_event(LOG_DISCONNECT, client->ip, "Too many clients");
            close(client_fd);
            continue;
        }


        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED); 

        if (pthread_create(&thread_id, &attr, handle_client, (void*)client) != 0)
        {
            perror("pthread"); 
            free(client); 
            close(client_fd); 
            continue; 
        }

        pthread_attr_destroy(&attr);
    }

    if (client_fd != -1)
        close(client_fd); 
}
