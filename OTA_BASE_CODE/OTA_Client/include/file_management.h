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

// Device config
#define DEVICE_ID "Device1"            
#define FIRMWARE_VERSION "V1.0"    
#define UPDATE_FIRMWARE_VERSION "V1.1"  

// MQTT CONFIGURATIONS
#define DEVICE_INFO_TOPIC "device/info"                                       //MQTT topic to read the device id and current version
#define FILE_TRANSFER_TOPIC "File/Transfer"                                   //MQTT topic to read the firmware update file
#define FILE_METADATA "File/Metadata"
#define BROKER_ADDRESS "dfd171ee7540472f9e5b2b1dfeb706b8.s1.eu.hivemq.cloud"  //Broker address used for MQTT connection
#define BROKER_PORT 8883                                                      //PORT number used to connect to the MQTT broker
#define USERNAME "hivemq.webclient.1733988288785"                             //username to connect to the MQTT broker
#define PASSWORD "q1NkSy;#,5D<30AweJEf"                                       //password used to connect to MQTT broker


// file reveive config
#define RECEIVED_FILE_PATH "received_firmware.bin"

// Saves the received MQTT payload to a file.
void save_received_file(const void *payload, size_t payloadlen);

// Sends an acknowledgment message to the MQTT broker.
void send_acknowledgment(struct mosquitto *mosq);

// Establishes a connection to the MQTT broker with specified settings.
int connect_to_mqtt_broker(struct mosquitto *mosq);

// Logs messages with the specified log level and format.
void logger(const char *level, const char *format, ...);


#endif // EXIM_FILE_MANAGEMENT_H

