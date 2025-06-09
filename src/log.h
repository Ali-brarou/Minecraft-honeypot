#ifndef LOG_H
#define LOG_H

#include "global.h"

typedef enum Log_event_e {
    LOG_CONNECT,
    LOG_DISCONNECT,
    LOG_FETCH_STATUS, 
    LOG_LOGIN, 
} Log_event_t; 

void logger_init(void); 
/* if there is no optional msg put NULL */  
void logger_handle_event(Log_event_t event, const char* ip, const char* optional_msg); 
void logger_close(void); 

#endif
