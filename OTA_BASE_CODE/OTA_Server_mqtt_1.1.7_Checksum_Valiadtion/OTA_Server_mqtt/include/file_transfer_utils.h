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
#include <pthread.h>     //pthread library for using POSIX threads
#include <curl/curl.h>   //libcurl library for making HTTP requests

#define MD5_DIGEST_LENGTH 16        // Length of an MD5 hash in bytes
#define MAX_RETRIES 5               // Maximum number of retry attempts
#define RECONNECT_DELAY 3           // Wait time before retrying (in seconds)
#define MAX_CLIENTS 100             //maximum number of clients the server can handle at a time
#define LOG_FILE "Logger_info.log"  //name of the log file where server logs will be stored

//external variables
extern const char *file_path;        //filepath where the updated file is stored to send to device
extern char *device_id;          // Global variable to store client IP
extern char **selected_devices;  //array to store the selected clients received from the UI
extern int selected_device_count;    //variable to count the number of selected clients in the selected clients array
extern char server_checksum[MD5_DIGEST_LENGTH * 2 + 1]; // Declare a buffer to store the MD5 checksum (hexadecimal format) of the server file
#define DOWNLOAD_BUFFER_SIZE 1024    // Defines a constant for the size of a buffer used for downloading data. 
extern const char *root_key;
extern size_t total_data_size;

// functions to send the updated file to the device
void send_file_in_bytes(struct mosquitto *mosq, const char *file_path, const char *device_id);

//function to check whether the connected device is in the selected device array or not
int is_device_selected(const char *device_id);

//function to read the selected devices data received from the UI
void parse_selected_devices(const char *clients_str);

//This function is used to clear or reset any stored data or status flags.
void reset_states();

//This function retrieves and initializes the selected devices for further processing.
void load_selected_devices();

//Fetches a file from the given URL and calculates its MD5 checksum.
int fetch_and_calculate_checksum(const char *url);

//Callback function for handling data received via libcurl.
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *data);

//logger module to log the messages
void logger(const char *level, const char *format, ...);

#endif //FILE_TRNSFER_UTILS_H