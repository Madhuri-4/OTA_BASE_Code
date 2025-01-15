CC = gcc
CFLAGS = -Iinclude -Wall -g

# Target executable
TARGET = publisher

# Source files
SRC = src/exim_library_mqtt.c src/parsing_device_data.c src/main.c

# Object files (replace .c with .o)
OBJ = $(SRC:.c=.o)

# Libraries
LIBS = -lmosquitto

# Set path for the Python script
PYTHON_SCRIPT = src/EXIM_SERVER.py

# Default target
all: $(TARGET)
	@echo "Build complete."
	@echo "Publisher executable created: $(TARGET)"
	@echo "Running the Python script..."
	# Set the LD_LIBRARY_PATH to include the current directory
	@export LD_LIBRARY_PATH=$(CURDIR):$$LD_LIBRARY_PATH && python3 $(PYTHON_SCRIPT) || echo "Error: Could not execute EXIM_SERVER.py."

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
