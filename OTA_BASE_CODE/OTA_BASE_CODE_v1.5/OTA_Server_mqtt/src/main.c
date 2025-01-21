/*
 * Copyright (c) 2025 Eximietas Design India Pvt. Ltd.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eximietas Design India Pvt. Ltd. 
 * proprietary license.
 *
 * File: main.c
 * Description:
 *    Main implementation file for the MQTT-based file transfer system.
 * 
 *    This file is a key component of the OTA (Over-the-Air) update system, responsible for:
 *    - Establishing MQTT connections.
 *    - Sending binary files (firmware updates) to client devices over the MQTT protocol.
 * 
 *    It reads the list of selected clients and the MQTT topic from environment variables,
 *    initializes the Mosquitto library, and ensures secure communication with the MQTT broker.
 * 
 * Key Functionalities:
 *    - Reads configuration (device list and selected clients) from environment variables.
 *    - Initializes the MQTT client and establishes a secure connection to the broker.
 *    - Sends firmware binary files in chunks to selected clients via MQTT topics.
 *    - Implements callback functions to handle incoming MQTT messages.
 * 
 *    This system enables secure and reliable distribution of firmware updates to devices,
 *    ensuring that large files are split into smaller chunks and securely transmitted using 
 *    TLS/SSL encryption.
 * 
 * Credits:
 *    - This software utilizes the **Mosquitto** MQTT broker library for message delivery 
 *      over the MQTT protocol. Mosquitto is an open-source message broker and a widely 
 *      adopted solution for IoT messaging systems.
 *      Visit: https://mosquitto.org/
 * 
 * Note:
 *    - Make sure the following environment variables are configured correctly:
 *      - DEVICE_LIST: Specifies the MQTT topic for device communication.
 *      - SELECTED_CLIENTS: Contains the list of client devices to be updated.
 * 
 * Company: Eximietas Design India Pvt. Ltd.
 * Author: Madhuri J M
 * Date: [Creation Date]
 * Version: 1.0
 */

#include "../include/exim_mqtt.h"
#include "../include/file_transfer_utils.h"

const char *file_path = "/OTA/Delta_packages/firmware_v1.2.bin"; // File path to store the send the update file to devices

char server_checksum[MD5_DIGEST_LENGTH * 2 + 1] = {0}; // Initialize buffer to store MD5 checksum (hex format) of server file, with null-terminator

/**
* Brief:
* sends a binary file in bytes to a client via the MQTT protocol.  
* publishes each bytes to a specific MQTT topic("File/Transfer/%s") associated with the client IP.
* 
* Parameters:
* mosq      - Pointer to the MQTT client instance.
* file_path - Path to the binary file to be sent.
* device_id - Device ID name used to send the firmware file.
*
* Return: NONE
*/
void send_file_in_bytes(struct mosquitto *mosq, const char *file_path, const char *device_id) {
    // Calculate the checksum of the server's file
    unsigned char *md5_hash = calculate_md5(file_path);

    if (md5_hash) { // Check if the MD5 hash was successfully calculated
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) { // Convert the MD5 hash (byte array) to a hexadecimal string
            sprintf(&server_checksum[i * 2], "%02x", md5_hash[i]); // Format each byte as two hexadecimal characters and store in server_checksum
        }
        server_checksum[MD5_DIGEST_LENGTH * 2] = '\0'; // Null terminate

        logger("INFO", "MD5 checksum: %s\n", server_checksum);
        free(md5_hash);  // Free the memory allocated for the MD5 hash
    } else {
        logger("ERROR", "Failed to calculate MD5 checksum.");
        return;
    }

    FILE *file = fopen(file_path, "rb");
    if (!file) {
        logger("ERROR", "Error opening file");
        return;
    }

    // Calculate the size of the binary file by seeking to the end of the file
    fseek(file, 0, SEEK_END);
    // Get the current position, which is the file size
    long file_size = ftell(file);
    // Reset the file pointer to the beginning of the file
    rewind(file);

    // If the file size is less than or equal to 0, print an error and exit
    if (file_size <= 0) {
        logger("ERROR", "Bin file size is invalid or empty: %ld bytes\n", file_size);
        fclose(file);
        return;
    }

    logger("DEBUG", "Bin file size: %ld bytes\n", file_size);

    // topic string for MQTT message with the given client IP
    char topic[256];
    snprintf(topic, sizeof(topic), "File/Transfer"); //getting issue when changed to logger

    // Declare a buffer to store chunks of data from the file
    char buffer[CHUNK_SIZE];

    // Variable to store the number of bytes read from the file
    size_t bytes_read;

    logger("DEBUG", "Sending file to %s...\n", device_id);
    // Read the file in chunks and publish each chunk via MQTT
    while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, file)) > 0) {
        //printf("Sending file of size %zu bytes to %s\n", bytes_read, ip); //getting issue when changed to logger
        // Clear retained message before publishing
        //exim_mosquitto_publish(mosq, NULL, "File/Transfer", 0, "", 0, true);

        exim_mosquitto_publish(mosq, NULL, topic, strlen(file_path), file_path, 0, false);
    }

    fclose(file);
    //printf("Bin file sent successfully to %s\n", ip); //getting issue when changed to logger  
}

/**
* Brief:
* Function to calculate the checksum (CRC32) of a file
* This checksum is used for verifying file integrity.
* 
* Parameters:
* file_path - The path of the file for which the MD5 checksum needs to be calculated.
*
* Return: 
* - Returns a pointer to an array containing the MD5 hash (checksum) of the file.
* - If the file cannot be opened or read, returns NULL.
*/ 
unsigned char* calculate_md5(const char *file_path) {
    logger("DEBUG", "File_path: %s\n", file_path);
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("Error opening file");
        return NULL;
    }

    MD5_CTX md5_ctx;     // MD5 context structure to hold the checksum state
    MD5_Init(&md5_ctx);  // Initialize the MD5 context for checksum calculation

    unsigned char buffer[1024]; // Buffer to store bytes of data read from the file
    size_t bytes_read; // Number of bytes read in each chunk

    // Read the file and update the MD5 checksum
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        MD5_Update(&md5_ctx, buffer, bytes_read); // Update the MD5 context with the data read
    }

    // Allocate memory for the MD5 hash (16 bytes)
    unsigned char *md5_hash = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
    MD5_Final(md5_hash, &md5_ctx);  // Finalize the MD5 hash

    fclose(file);
    return md5_hash;
}


/**
 * Brief:
 * This program establishes an MQTT connection using the Mosquitto library to facilitate communication
 * between a server and selected clients. The MQTT topic and client list are read from environment variables.
 * It initializes the Mosquitto library, creates an MQTT client, connects to the broker, and processes
 * incoming messages.
 * 
 * Parameters: None
 * 
 * getenv:
 * - DEVICE_LIST     : Environment variable set by the UI that specifies the MQTT topic for communication.
 * - SELECTED_CLIENTS: Environment variable set by the UI that contains a list of selected client devices.
 * 
 * Return: 
 *  - 0 on successful execution.
 *  - 1 if there are errors during initialization or execution.
 */
int main() {
    struct mosquitto *mosq;
    int rc; // the rc code of the broker connection


    // Reading the MQTT topic from an environment variable set by the UI, which specifies the selected clients list.
    char *ui_mqtt_topic = getenv("DEVICE_LIST");
    if (ui_mqtt_topic == NULL) {
        logger("ERROR", "DEVICE_LIST environment variable not set.\n");
        return 1;
    }

    // Reading the SELECTED CLIENTS list from the UI as an environment variable
    char *selected_devices_str = getenv("SELECTED_DEVICES");
    if (selected_devices_str == NULL) {
         logger("ERROR", "SELECTED_DEVICES environment variable not set.\n");
         return 1;
    }

    // Check whether the device IP is in the selected clients list
    parse_selected_devices(selected_devices_str);

    // Initialize mosquitto library for mqtt operations
    exim_mosquitto_lib_init();

    // Create a new Mosquitto instance used for MQTT communication
    mosq = exim_mosquitto_new(NULL, true, NULL);
    if (!mosq) {
        logger("ERROR", "Error: Unable to create Mosquitto client\n");
        return 1;
    }

    // Set username and password for HiveMQ Cloud
    exim_mosquitto_username_pw_set(mosq, USERNAME, PASSWORD);

    // Set TLS/SSL parameters
    rc = exim_mosquitto_tls_set(mosq, "/etc/ssl/certs/ca-certificates.crt", NULL, NULL, NULL, NULL);
    if (rc != MOSQ_ERR_SUCCESS) {
        logger("ERROR", "Failed to configure TLS: %s\n", mosquitto_strerror(rc));
        exim_mosquitto_destroy(mosq);
    } else {
        logger("INFO", "TLS configuration successful.\n");
    }
    
    // Retry connection logic
    // while (attempt < MAX_RETRIES) {
    //     rc = exim_mosquitto_connect(mosq, BROKER_ADDRESS, BROKER_PORT, 60);
    //     if (rc == MOSQ_ERR_SUCCESS) {
    //         logger("INFO", "Connected to MQTT broker successfully.\n");
    //         break;  // Exit retry loop on success
    //     } else {
    //         logger("ERROR", "MQTT connection failed: %s\n", exim_mosquitto_strerror(rc));
    //         logger("INFO", "Retrying in %d seconds... (Attempt %d/%d)\n", RECONNECT_DELAY, attempt + 1, MAX_RETRIES);
    //         sleep(RECONNECT_DELAY);
    //     }
    //     attempt++;
    // }
    // // Exit if all retries fail
    // if (attempt == MAX_RETRIES) {
    //     logger("ERROR", "Failed to connect after %d attempts. Exiting.\n", MAX_RETRIES);
    //     exim_mosquitto_destroy(mosq);
    //     exim_mosquitto_lib_cleanup();
    //     return 1;
    // }
    // Connect to the MQTT broker
    rc = exim_mosquitto_connect(mosq, BROKER_ADDRESS, BROKER_PORT, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        logger("ERROR", "Error: Unable to connect to MQTT broker. %s\n", exim_mosquitto_strerror(rc));
        return 1;
    }

    // Set callbacks for MQTT connection and read messages from the devices
    exim_mosquitto_connect_callback_set(mosq, exim_on_connect);
    exim_mosquitto_message_callback_set(mosq, exim_on_message);
    // Start the MQTT loop to continuously process incoming messages
    exim_mosquitto_loop_forever(mosq, -1, 1);
    
    //Cleans up and frees resources associated with the Mosquitto client instance.
    exim_mosquitto_destroy(mosq);
    exim_mosquitto_lib_cleanup();

    return 0;
}
