#ifndef FILE_MANAGEMENT_H
#define FILE_MANAGEMENT_H

#include <mosquitto.h>  // Include for Mosquitto-related types
#include <stdio.h>      // Standard I/O operations
#include <stdlib.h>     // memory allocation, process control, etc.
#include <string.h>     // String handling functions
#include <time.h>       // Functions for time manipulation and retrieval
#include <stdarg.h>     // Support for variable argument functions
#include <sys/stat.h>   // Provides functions to obtain file status information, such as size and permissions.
#include <unistd.h>     // Provides access to the POSIX operating system API, including file and process operations.
#include <zlib.h>
#include <curl/curl.h>


// Buffer size for file reading
#define BUFFER_SIZE 8192

// Device config
#define DEVICE_ID "OTA_Client_NA1"        
#define FIRMWARE_VERSION "V1.0"    
#define UPDATE_FIRMWARE_VERSION "V1.1"

// Time in seconds between reconnections
#define MAX_RETRIES 5       // Maximum number of retry attempts
#define RECONNECT_DELAY 3  // Wait time before retrying (in seconds)
#define MAX_CLIENTS 100
#define LOG_FILE "Logger_info.log"
#define LOCAL_FILE_PATH "downloaded_firmware.bin"


// MQTT CONFIGURATIONS
#define DEVICE_INFO_TOPIC "device/info"                                       //MQTT topic to read the device id and current version
#define FILE_TRANSFER_TOPIC "File/Transfer/OTA_Client_NA1"                                   //MQTT topic to read the firmware update file
#define FILE_METADATA "File/Metadata"
#define BROKER_ADDRESS "dfd171ee7540472f9e5b2b1dfeb706b8.s1.eu.hivemq.cloud"  //Broker address used for MQTT connection
#define BROKER_PORT 8883                                                      //PORT number used to connect to the MQTT broker
#define USERNAME "hivemq.webclient.1733988288785"                             //username to connect to the MQTT broker
#define PASSWORD "q1NkSy;#,5D<30AweJEf"                                       //password used to connect to MQTT broker

//constants
extern unsigned long device_crc;
extern char *bin_filename;
extern char *file_checksum;

// Saves the received MQTT payload to a file.
void save_received_file(const void *payload, size_t payloadlen);

// Sends an acknowledgment message to the MQTT broker.
void send_acknowledgment(struct mosquitto *mosq);

// Establishes a connection to the MQTT broker with specified settings.
int connect_to_mqtt_broker(struct mosquitto *mosq);

// Logs messages with the specified log level and format.
void logger(const char *level, const char *format, ...);

// publish periodic device ID and version 
void* exim_periodic_publish(void *arg);

// Downloads a file from the specified URL and saves it to the given local path.
int download_file(const char *payload, const char *local_path);

// Calculates the MD5 checksum of the file at the specified path.
int calculate_md5(const char *file_path, unsigned char *result);

// Converts an MD5 checksum to its hexadecimal string representation.
void md5_to_hex(const unsigned char *md5, char *hex);

// Callback function to write data to a file during a file download operation.
size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream);

#endif // EXIM_FILE_MANAGEMENT_H
