#include "global.h"
#include "server.h"
#include "log.h"

int main(void)
{
    logger_init(); 
    signal(SIGINT, server_handle_sigint); 

    int listen_fd = setup_server(); 
    if (listen_fd == -1)
    {
        fprintf(stderr, "Server setup failed :'(\n"); 
        return 1; 
    }

    printf("Listening on port %s\n", PORT); 
    accept_loop(listen_fd); 

    printf("Terminating safely\n"); 
    logger_close(); 
    return 0; 
}
