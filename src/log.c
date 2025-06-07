#include "log.h"

static FILE *log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void logger_init(void)
{
    printf("Opening log file : %s\n", LOG_FILE_PATH); 
    log_file = fopen(LOG_FILE_PATH, "a"); /* append mode */ 
    if (!log_file)
    {
        perror("fopen"); 
        exit(1); 
    }
}

void logger_handle_event(Log_event_t event, char* ip)
{
    char* log_msg; 
    switch(event)
    {
        case LOG_CONNECT: 
            log_msg = "Connected"; 
            break; 
        case LOG_DISCONNECT: 
            log_msg = "Disconnected"; 
            break; 
        case LOG_FETCH_STATUS: 
            log_msg = "Requested status"; 
            break; 
        default: 
            fprintf(stderr, "bad log event\n"); 
            return; 
    }
    //get current time 
    time_t tm;
    time(&tm);
    pthread_mutex_lock(&log_mutex);
    fprintf(log_file, "%s: %s on %s",ip, log_msg, ctime(&tm)); 
    fflush(log_file); 
    pthread_mutex_unlock(&log_mutex);
}

void logger_close(void)
{
    pthread_mutex_lock(&log_mutex);
    if (log_file)
    {
        fclose(log_file); 
        log_file = NULL; 
    }
    pthread_mutex_unlock(&log_mutex);

    pthread_mutex_destroy(&log_mutex);
}
