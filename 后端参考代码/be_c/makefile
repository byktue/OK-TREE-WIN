# Makefile for the Simulated Network Disk Project

# Compiler and flags
CC = gcc
CFLAGS = -Wall -g  # -Wall enables all warnings, -g adds debug info
LDFLAGS_SERVER = -lsqlite3 -lpthread -ljson-c -lcrypto
LDFLAGS_CLIENT = -ljson-c -lcrypto -lpthread
LDFLAGS_INITDB = -lsqlite3

# Executable names
SERVER_EXEC = server
CLIENT_EXEC = client
INITDB_EXEC = init_db

# Source files
SERVER_SRC = server.c
CLIENT_SRC = client.c
INITDB_SRC = init_db.c

# Phony targets
.PHONY: all clean

# Default target
all: $(SERVER_EXEC) $(CLIENT_EXEC) $(INITDB_EXEC)

# Rule to build the server
$(SERVER_EXEC): $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS_SERVER)

# Rule to build the client
$(CLIENT_EXEC): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS_CLIENT)

# Rule to build the database initializer
$(INITDB_EXEC): $(INITDB_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS_INITDB)

# Clean up build artifacts
clean:
	rm -f $(SERVER_EXEC) $(CLIENT_EXEC) $(INITDB_EXEC) *.o
