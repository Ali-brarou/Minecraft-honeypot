TARGET = minecraft-honey
CC = gcc
CFLAGS = -Wall -Wextra -Werror 
#for maximum protection
CFLAGS += -fstack-protector-all 
CFLAGS += -O2 -D_FORTIFY_SOURCE=2 
CFLAGS += -pie -fPIE
CFLAGS += -Wl,-z,relro,-z,now
CFLAGS +=  -Wl,--as-needed
SRCS = main.c server.c honeypot.c log.c

all: $(TARGET)

$(TARGET): $(SRCS) 
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET)

clean: 
	rm -rf $(TARGET)
