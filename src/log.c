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

    struct stat st = {0}; 
    if (stat(LOG_DIR_PATH, &st) == -1)
    {
        
        printf("Creating payload logs dir : %s\n", LOG_DIR_PATH); 
        if (mkdir(LOG_DIR_PATH, 0700) == -1)
        {
            perror("mkdir"); 
            exit(1); 
        }
    }
    else 
    {
        if (!S_ISDIR(st.st_mode))
        {
            fprintf(stderr, "Error: %s is not a directory\n", LOG_DIR_PATH); 
            exit(1); 
        }
    }
}

void logger_handle_event(Log_event_t event, const char* ip, const char* optional_msg)
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
        case LOG_LOGIN: 
            log_msg = "Tried to login"; 
            break; 
        default: 
            fprintf(stderr, "bad log event\n"); 
            return; 
    }
    //get current time 
    time_t tm;
    time(&tm);
    pthread_mutex_lock(&log_mutex);
    if (optional_msg == NULL)
    {
        fprintf(log_file, "[%s] %s on %s",ip, log_msg, ctime(&tm)); 
#if VERBOSE
        printf("[%s] %s on %s",ip, log_msg, ctime(&tm)); 
#endif
    }
    else
    {
        fprintf(log_file, "[%s] %s (%s) on %s",ip, log_msg, optional_msg, ctime(&tm)); 
#if VERBOSE
        printf("[%s] %s (%s) on %s",ip, log_msg, optional_msg, ctime(&tm)); 
#endif
    }
    fflush(log_file); 
    pthread_mutex_unlock(&log_mutex);
}

void logger_save_payload(const char* ip, const char* phase, const uint8_t* payload, size_t len)
{
    pthread_mutex_lock(&log_mutex);
    char filename[512]; 
    time_t now = time(NULL); 
    snprintf(filename, sizeof filename, "%s/%s_%s_%ld.bin", LOG_DIR_PATH, ip, phase, now); 
    FILE* payload_file = fopen(filename, "wb"); 
    if (payload_file)
    {
        fwrite(payload, 1, len, payload_file); 
        fclose(payload_file); 
#if VERBOSE 
    printf("Saved payload from %s (%s) to %s\n", ip, phase, filename);
#endif 
    }
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
