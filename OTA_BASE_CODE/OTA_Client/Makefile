# # Compiler and flags
# CC = gcc
# CFLAGS = -Iinclude -Wall -g

# # Target executable
# TARGET = OTA

# # Source files
# SRC = src/exim_library_mqtt.c src/file_management.c src/main.c

# # Object files (replace .c with .o)
# OBJ = $(SRC:.c=.o)

# # Libraries
# LIBS = -lmosquitto

# # Default target
# all: $(TARGET)

# # Build target
# $(TARGET): $(OBJ)
# 	$(CC) -o $@ $^ $(LIBS)

# # Compile source files to object files
# %.o: %.c
# 	$(CC) $(CFLAGS) -c $< -o $@

# # Clean up build files
# clean:
# 	rm -f $(OBJ) $(TARGET)

# # Phony targets
# .PHONY: all clean
# Compiler and flags
# Compiler and flags
CC = gcc
CFLAGS = -Iinclude -Wall -g

# Target executable
TARGET = OTA

# Source files
SRC = src/exim_library_mqtt.c src/file_management.c src/main.c

# Object files (replace .c with .o)
OBJ = $(SRC:.c=.o)

# Libraries
LIBS = -lmosquitto

# Default target
all: $(TARGET)
	@echo "Build complete."
	@echo "Executing the target..."
	@echo "-----------------------" 
	@./$(TARGET) || echo "Error: Could not execute $(TARGET)."

# Build target
$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LIBS)

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
