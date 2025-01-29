# Compiler and flags
CC = gcc
CFLAGS = -I/usr/include -Iinclude -Wall -g -Wno-deprecated-declarations
LDFLAGS = -L/usr/lib -lcurl -lmosquitto -lcrypto -lssl -ljson-c -lz

# Target executable
TARGET = OTA

# Source files
SRC = src/exim_library_mqtt.c src/file_management.c src/main.c

# Object files (replace .c with .o)
OBJ = $(SRC:.c=.o)

# Default target
all: $(TARGET)
	@echo "Build complete."
	@echo "-----------------------" 
	@echo "Executing the target..."
	@./$(TARGET) || echo "Error: Could not execute $(TARGET)."

# Build target
$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "Object file $@ created."

# Clean up build files
clean:
	rm -f $(OBJ) $(TARGET)
	@echo "Cleaned up build files."

# Phony targets
.PHONY: all clean
