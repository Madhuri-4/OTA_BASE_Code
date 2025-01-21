/*
 * Copyright (c) 2025 Eximietas Design India Pvt. Ltd.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eximietas Design India Pvt. Ltd. 
 * proprietary license.
 *
 * File: file_management.c
 * Description:
 *    This C file is part of the Eximietas Design India Pvt. Ltd.'s library for implementing 
 *    MQTT-based communication for file transfer and firmware updates. 
 *    It contains key functions to handle the receive the firmware files via MQTT, saving the 
 *    received data to file, and sending acknowledgments to the MQTT broker. The file also 
 *    includes logging functionality to track operations and errors.
 * 
 * Key Functionalities:
 *    - Receive and save firmware files sent over MQTT.
 *    - Send acknowledgment messages containing device information and firmware update status.
 *    - Provide logging functionality for monitoring and debugging.
 *    - Establish a secure and authenticated MQTT connection to the broker.
 * 
 * Dependencies:
 *    - Mosquitto MQTT library: Provides core MQTT functionality.
 *    - file_transfer_utils.h: Utility functions for handling file transfers.
 * 
 * Credits:
 *    - This software utilizes the **Mosquitto** MQTT broker library for message delivery 
 *      over the MQTT protocol. Mosquitto is an open-source message broker and a widely 
 *      adopted solution for IoT messaging systems.
 *      Visit: https://mosquitto.org/
 * 
 * Company: Eximietas Design India Pvt. Ltd.
 * Author: Ramesh
 * Date: [Creation Date]
 * Version: 1.0
 */
#include "../include/file_management.h"
#include "../include/exim_mqtt.h"
#include <openssl/md5.h>

#define RECEIVED_FILE_PATH "/home/madhurijinka/Documents/OTA_files/firmwarev1.2.bin" //file path to store the received file

char *bin_filename = NULL;
//char *file_checksum;
char server_file_checksum[33]; // 32 hex characters + null terminator

// Function to calculate the checksum (CRC32) of a file
unsigned char* calculate_md5(const char *bin_filename) {
    FILE *file = fopen(bin_filename, "rb");
    if (!file) {
        perror("Error opening file");
        return NULL;
    }

    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);  // Initialize MD5 context

    unsigned char buffer[1024];
    size_t bytes_read;

    // Read the file and update the MD5 checksum
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        MD5_Update(&md5_ctx, buffer, bytes_read);
    }

    unsigned char *md5_hash = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
    MD5_Final(md5_hash, &md5_ctx);  // Finalize the MD5 hash

    fclose(file);
    return md5_hash;
}

void print_md5(unsigned char *md5_hash) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", md5_hash[i]);
    }
    printf("\n");
}

/**
 * Brief:
 * This function saves the received payload to a file specified by RECEIVED_FILE_PATH.
 * It writes the payload as binary data and logs the success or failure of the operation.
 * 
 * Parameters: 
 *  - payload: Pointer to the data to be saved.
 *  - payloadlen: Length of the data in bytes.
 * 
 * Return: None
 */
void save_received_file(const void *payload, size_t payloadlen) {
    char extracted_path[512];
    

    // Ensure payload is null-terminated (if not, handle accordingly)
    if (payloadlen >= sizeof(extracted_path)) {
        printf("Payload too large to handle.\n");
        return;
    }

    // Copy payload to a local buffer and null-terminate
    memcpy(extracted_path, payload, payloadlen);
    extracted_path[payloadlen] = '\0';
    unsigned char *file_checksum = calculate_md5(payload);
    if (file_checksum) {
        printf("MD5 checksum for file_path from server: ");
        print_md5(file_checksum);

        // Convert checksum to hex string and store in `server_file_checksum`
        for (int i = 0; i < 16; i++) {
            sprintf(&server_file_checksum[i * 2], "%02x", file_checksum[i]);
        }
        server_file_checksum[32] = '\0'; // Null-terminate

        free(file_checksum);
    } else {
        printf("Failed to calculate MD5 checksum.\n");
    }

    // Find the .bin filename in the payload
    /*bin_filename = strrchr(extracted_path, '/');
    if (bin_filename) {
        bin_filename++; // Move past the '/' character
    } else {
        printf("Invalid file path in payload: %s\n", extracted_path);
        return;
    }
    printf("bin filename: %s\n", bin_filename);*/
    

    

    FILE *file = fopen(RECEIVED_FILE_PATH, "wb"); // Append binary data
    if (file) {
        //fwrite(payload, 1, payloadlen, file);
        fwrite("Hi ", 1, 2, file);
        fclose(file);
        printf("Received firmware file.\n");
        unsigned char *md5_hash = calculate_md5(RECEIVED_FILE_PATH);
        printf("received file path: %s\n", RECEIVED_FILE_PATH);
        if (md5_hash) {
        printf("MD5 checksum for new_file: ");
        print_md5(md5_hash);
        free(md5_hash);  // Free the memory allocated for the MD5 hash
        } else {
            printf("Failed to calculate MD5 checksum.\n");
        }
        // Calculate the checksum of the received file
        /*device_crc = (long)calculate_md5(bin_filename);
        printf("Device checksum: %lx\n", device_crc);*/
        //char checksum_payload[64];
        //snprintf(checksum_payload, sizeof(checksum_payload), "%lx", device_crc);
    } else {
        printf("Error opening file for writing.\n");
    }
    

}

/**
 * Brief:
 * Sends an acknowledgment message to the MQTT broker containing the device ID,
 * file size, and updated firmware version. The message is published to a 
 * predefined acknowledgment topic.
 * 
 * Parameters: 
 * - mosq: Pointer to the Mosquitto client instance used for publishing messages.
 * 
 * Return: None
 */
void send_acknowledgment(struct mosquitto *mosq) {
    char ack_message[256];
    snprintf(ack_message, sizeof(ack_message), "Device ID:%s Device checksum: %s, UPDATE_FIRMWARE_VERSION %s", DEVICE_ID, server_file_checksum,UPDATE_FIRMWARE_VERSION);
    char ack_topic[512];
    snprintf(ack_topic, sizeof(ack_topic), "File/Ack");
    exim_mosquitto_publish(mosq, NULL, ack_topic, 0, "", 0, true);
    exim_mosquitto_publish(mosq, NULL, ack_topic, strlen(ack_message), ack_message, 0, false);
    printf("Sent acknowledgment: %s\n", ack_message);
}

/**
 * Breif:
 * The logger function writes log messages to both the console and a log file (Logger_info.log). 
 * It adds a timestamp and log level (e.g., INFO, DEBUG, ERROR) to each message.
 * 
 * Parameters:
 * level  - A string representing the log level (e.g., "INFO", "DEBUG", "ERROR").
 * format - A format string describing the message to log.
 * ...    - Variable arguments corresponding to the format specifiers in the format string.
 * 
 * Return: NONE 
 */
void logger(const char *level, const char *format, ...) {
    FILE *log_file = fopen("Logger_info.log", "a");
    if (!log_file) {
        // Directly print the error message instead of calling logger
        fprintf(stderr, "[ERROR] Unable to open log file for writing.\n");
        return;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // Prepare the timestamp
    char timestamp[64];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);

    // Write to console
    printf("[%s] [%s] ", timestamp, level);

    // Write to file
    fprintf(log_file, "[%s] [%s] ", timestamp, level);

    // Handle variable arguments
    va_list args;
    va_start(args, format);
    vprintf(format, args);               // Print to console
    vfprintf(log_file, format, args);    // Write to file
    va_end(args);

   
    fprintf(log_file, "\n");

    fclose(log_file);
}

/**
 * Brief:
 * Establishes a connection to an MQTT broker with the provided Mosquitto client instance.
 * Configures the username, password, and TLS settings before attempting to connect.
 * Sets callbacks for handling connection and incoming messages.
 * 
 * Parameters:
 * - mosq: Pointer to the Mosquitto client instance used for the connection.
 * 
 * Return: 
 * - EXIT_SUCCESS (0) on successful connection to the broker.
 * - EXIT_FAILURE (1) or -1 on error, indicating the failure reason.
 */
int connect_to_mqtt_broker(struct mosquitto *mosq) {
    
    if (!mosq) {
        fprintf(stderr, "Failed to create Mosquitto client instance.\n");
        return EXIT_FAILURE;
    }
    if (exim_mosquitto_username_pw_set(mosq, USERNAME, PASSWORD) != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Failed to set username and password.\n");
        exim_mosquitto_destroy(mosq);
        return -1;
    }

    // Set up TLS with the system CA bundle
    const char *cafile_path = "/etc/ssl/certs/ca-certificates.crt";
    if (exim_mosquitto_tls_set(mosq, cafile_path, NULL, NULL, NULL, NULL) != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Failed to configure TLS.\n");
        exim_mosquitto_destroy(mosq);
        return -1;
    }
    // Connect to the broker
    printf("Connecting to broker...\n");
    if (exim_mosquitto_connect(mosq, BROKER_ADDRESS, BROKER_PORT, 60) != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Failed to connect to broker.\n");
        mosquitto_destroy(mosq);
        return EXIT_FAILURE;
    }
    // Set callbacks
    exim_mosquitto_connect_callback_set(mosq, exim_on_connect);
    exim_mosquitto_message_callback_set(mosq, exim_on_message);

    return EXIT_SUCCESS;
}