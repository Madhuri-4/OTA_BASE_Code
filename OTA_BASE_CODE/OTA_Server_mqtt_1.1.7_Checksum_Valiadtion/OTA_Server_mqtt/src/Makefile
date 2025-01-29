CC = gcc
CFLAGS = -Wall -g

# Target executable
TARGET = publisher

# Source files for C compilation
SRC = src/exim_library_mqtt.c src/main.c src/parsing_device_data.c

# Object files (replace .c with .o)
OBJ = $(SRC:.c=.o)

# Libraries
LIBS = -lmosquitto -lcrypto -Wno-deprecated-declarations

# Default target
all: run_python $(TARGET)
	@echo "Build complete."
	@echo "Running the executable..."
	@./$(TARGET) || echo "Error: Could not execute $(TARGET)."

# Run the Python script first
run_python:
	@echo "Running Python script EXIM_SERVER.py..."
	@python3 EXIM_SERVER.py || echo "Error: Could not run EXIM_SERVER.py"

# Build the executable
$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LIBS)

# Compile C source files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "Object file $@ created."

# Clean up build files
clean:
	rm -f $(OBJ) $(TARGET)
	@echo "Cleaned up build files."

# Phony targets
.PHONY: all clean run_python
