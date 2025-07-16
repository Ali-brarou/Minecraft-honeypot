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
/* if there is no optional msg pass NULL */  
void logger_handle_event(Log_event_t event, const char* ip, const char* optional_msg); 
void logger_save_payload(const char* ip, const char* phase, const uint8_t* payload, size_t len); 
void logger_close(void); 

#endif
