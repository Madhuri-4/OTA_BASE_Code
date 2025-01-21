#ifndef FILE_TRNSFER_UTILS_H
#define FILE_TRNSFER_UTILS_H

#include <mosquitto.h>   // Include for Mosquitto-related types
#include <stdbool.h>     // Standard boolean library for boolean operations
#include <stdio.h>       // Standard I/O operations
#include <stdlib.h>      // memory allocation, process control, etc.
#include <string.h>      // String handling functions
#include <time.h>        // Functions for time manipulation and retrieval
#include <stdarg.h>      // Support for variable argument functions
#include <errno.h>       // Provides error codes for system calls and library functions.
#include <openssl/md5.h> // Include OpenSSL MD5 header for MD5 hash functions
#include <unistd.h>      //for sleep() function
#include <pthread.h>

//Mocro used for finding the server file checksum
#define MD5_DIGEST_LENGTH 16

// Time in seconds between reconnections
#define MAX_RETRIES 5       // Maximum number of retry attempts
#define RECONNECT_DELAY 3  // Wait time before retrying (in seconds)
#define MAX_CLIENTS 100
#define LOG_FILE "Logger_info.log"

//external variables
extern const char *file_path;        //filepath where the updated file is stored to send to device
extern char *device_id;          // Global variable to store client IP
extern char **selected_devices;  //array to store the selected clients received from the UI
extern int selected_device_count;    //variable to count the number of selected clients in the selected clients array
extern char server_checksum[MD5_DIGEST_LENGTH * 2 + 1]; // Declare a buffer to store the MD5 checksum (hexadecimal format) of the server file

// functions to send the updated file to the device
void send_file_in_bytes(struct mosquitto *mosq, const char *file_path, const char *device_id);

// Function to calculate the MD5 checksum of a file, returns the checksum as a byte array
unsigned char *calculate_md5(const char *file_path);

//function to check whether the connected device is in the selected device array or not
int is_device_selected(const char *device_id);

//function to read the selected devices data received from the UI
void parse_selected_devices(const char *clients_str);

void reset_states();

void load_selected_devices();

//logger module to log the messages
void logger(const char *level, const char *format, ...);
#endif //FILE_TRNSFER_UTILS_H