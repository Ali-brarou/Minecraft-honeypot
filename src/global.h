#ifndef GLOBAL_H
#define GLOBAL_H

#include <sys/types.h>
#include <fcntl.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h> 
#include <string.h> 
#include <stdlib.h> 
#include <stdio.h> 
#include <pthread.h> 
#include <time.h> 
#include <sys/time.h> 
#include <errno.h> 
#include <signal.h>

#define PORT "25565" /* default minecraft port */
#define BACKLOG 10
#define CLIENT_TIMEOUT_SEC 10
#define FAKE_STATUE_FILE_PATH "fake_status"
#define BUFFER_SIZE 1024
#define FAKE_STATUS "{\"version\":{\"name\":\"1.21.5\",\"protocol\":770},\"enforcesSecureChat\":false,\"description\":\"A Minecraft Server\",\"players\":{\"max\":69,\"online\":0}}"
#define LOG_FILE_PATH "./log.txt"


#endif
