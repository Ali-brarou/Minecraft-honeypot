#ifndef SERVER_H
#define SERVER_H

#include "global.h"
#include "honeypot.h"

int setup_server(void); 
void accept_loop(int listen_fd); 
void server_handle_sigint(int sig); 

#endif
