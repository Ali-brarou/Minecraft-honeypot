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
#include <stdarg.h> 
#include <pthread.h> 
#include <time.h> 
#include <sys/time.h> 
#include <errno.h> 
#include <signal.h>
#include <stdatomic.h>
#include <sys/stat.h> 

extern atomic_int current_clients;  

#define PORT "25565" /* default minecraft port */
#define BACKLOG 512
#define MAX_CLIENTS 1000
#define CLIENT_TIMEOUT_SEC 3
#define BUFFER_SIZE 4096

#define FAKE_STATUS "{\"version\":{\"name\":\"1.21.5\",\"protocol\":770},\"enforcesSecureChat\":false,\"description\":\"§6A Minecraft Honeypot. Check §ahttps://github.com/Ali-brarou/Minecraft-honeypot\",\"players\":{\"max\":69,\"online\":3,\"sample\":[{\"name\":\"Notch\",\"id\":\"b50ad385-829d-3141-a216-7e7d7539ba7f\"},{\"name\":\"Floppy\",\"id\":\"b8e17beb-6bad-35d1-9f78-823c694adf84\"},{\"name\":\"Teto\",\"id\":\"8835cc98-43a2-35a4-a6f2-96a136c82093\"}]}}"

#define DISCONNECT_MSG "{\"text\":\"§cNot a real server. Check https://github.com/Ali-brarou/Minecraft-honeypot!\"}"

#define LEGACY_PING_RESP \
  "\xff\x00\x25\x00\xa7\x00\x31\x00\x00\x00\x31\x00\x32\x00\x37\x00\x00" \
  "\x00\x31\x00\x2e\x00\x32\x00\x31\x00\x2e\x00\x35\x00\x00\x00\x41\x00" \
  "\x20\x00\x4d\x00\x69\x00\x6e\x00\x65\x00\x63\x00\x72\x00\x61\x00\x66" \
  "\x00\x74\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00" \
  "\x00\x00\x33\x00\x00\x00\x32\x00\x30"
#define LEGACY_PING_RESP_LEN 77


#define VERBOSE 1  /* If set, logs will also be printed to stdout; otherwise, only to the log file */
#define LOG_FILE_PATH "./log.txt"
#define LOG_DIR_PATH  "logs" /* used to save payloads */ 


#endif
