#ifndef LOG_H
#define LOG_H

#include "global.h"

typedef enum Log_event_e {
    LOG_CONNECT,
    LOG_DISCONNECT,
    LOG_FETCH_STATUS, 
} Log_event_t; 

void logger_init(void); 
void logger_handle_event(Log_event_t event, char* ip); 
void logger_close(void); 

#endif
