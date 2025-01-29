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
 * Date: 15/01/2025
 * Version: 1.0
 */

#include "../include/exim_mqtt.h"
#include "../include/file_transfer_utils.h"

const char *file_path = "https://raw.githubusercontent.com/Madhuri-4/OTA_BASE_Code/main/OTA_BASE_CODE/firmware_v1.0.bin";
const char *firmware_file = "firmware_v1.0.bin";

char server_checksum[MD5_DIGEST_LENGTH * 2 + 1] = {0}; // Initialize buffer to store MD5 checksum (hex format) of server file, with null-terminator
size_t total_data_size = 0;

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

    // Fetch the file content from the URL and calculate its checksum
    if (fetch_and_calculate_checksum(file_path) != 0) {
        fprintf(stderr, "Failed to fetch file or calculate checksum.\n");
        return;
    }
    char topic[256];
    char payload[256];
    snprintf(topic, sizeof(topic), "File/Transfer/%s", device_id);
    snprintf(payload, sizeof(payload), "%s:%s", file_path, server_checksum);

    // Send the URL of the firmware file
    exim_mosquitto_publish(mosq, NULL, topic, strlen(payload), payload, 0, false);
    printf("Sent update %s\n", (char*)payload); //facing issue when changed to logger
  
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
