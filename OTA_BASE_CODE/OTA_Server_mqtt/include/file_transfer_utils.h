#ifndef FILE_TRNSFER_UTILS_H
#define FILE_TRNSFER_UTILS_H

#include <mosquitto.h> // Include for Mosquitto-related types
#include <stdbool.h>   // Standard boolean library for boolean operations
#include <stdio.h>     // Standard I/O operations
#include <stdlib.h>    // memory allocation, process control, etc.
#include <string.h>    // String handling functions
#include <time.h>      // Functions for time manipulation and retrieval
#include <stdarg.h>    // Support for variable argument functions
#include <errno.h>     // Provides error codes for system calls and library functions.
#include <openssl/md5.h> // For MD5
#include <openssl/evp.h>

//external variables
extern const char *file_path;        //filepath where the updated file is stored to send to device
extern char *device_id;          // Global variable to store client IP
extern char **selected_devices;  //array to store the selected clients received from the UI
extern int selected_device_count;    //variable to count the number of selected clients in the selected clients array

// functions to send the updated file to the device
void send_file_in_bytes(struct mosquitto *mosq, const char *file_path, const char *device_id);

//function to check whether the connected device is in the selected device array or not
int is_device_selected(const char *device_id);

//function to read the selected devices data received from the UI
void parse_selected_devices(const char *clients_str);

//logger module to log the messages
void logger(const char *level, const char *format, ...);
#endif //FILE_TRNSFER_UTILS_H