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
 * Date: 15/01/2025
 * Version: 1.0
 */
#include "../include/file_management.h"
#include "../include/exim_mqtt.h"
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>

char *bin_filename = NULL;
//char *file_checksum;
char server_file_checksum[33]; // 32 hex characters + null terminator

char server_checksum[MD5_DIGEST_LENGTH * 2 + 1];

/**
 * Brief:
 * Processes a received payload containing a URL and checksum. Downloads the file from 
 * the URL, calculates its MD5 checksum, and compares it with the provided checksum 
 * to verify file integrity.
 * 
 * Parameters:
 * - payload: Pointer to the raw payload containing the URL and checksum in the format 
 *            "URL:checksum".
 * - payloadlen: Length of the received payload.
 * 
 * Return:
 * - This function does not return a value. It prints appropriate messages for success or failure.
 *
 */
void save_received_file(const void *payload, size_t payloadlen) {
    char extracted_url[512] = {0};
    char server_checksum[65] = {0}; // To store the checksum (64 chars + null terminator)
    char original_checksum[65] = {0}; // To store the original checksum from the device
    char file_url_checksum[65] = {0}; // To store the calculated checksum of the downloaded file

    // Ensure payload length is within a valid range
    if (payloadlen >= sizeof(extracted_url)) {
        fprintf(stderr, "Payload too large to handle.\n");
        return;
    }

    // Copy payload to a local buffer
    char payload_copy[512] = {0};
    memcpy(payload_copy, payload, payloadlen);
    payload_copy[payloadlen] = '\0'; // Ensure null-termination

    printf("Original payload: %s\n", payload_copy);

    // Find the position of the last colon (separator between URL and checksum)
    char *separator = strrchr(payload_copy, ':');
    if (!separator) {
        fprintf(stderr, "Invalid payload format. No checksum found.\n");
        return;
    }

    // Split the payload into URL and checksum
    size_t url_length = separator - payload_copy;
    if (url_length >= sizeof(extracted_url)) {
        fprintf(stderr, "URL too long to handle.\n");
        return;
    }

    // Extract the URL
    strncpy(extracted_url, payload_copy, url_length);
    extracted_url[url_length] = '\0'; // Null-terminate the URL

    // Extract the checksum from the device's payload
    strncpy(original_checksum, separator + 1, sizeof(original_checksum) - 1);
    original_checksum[sizeof(original_checksum) - 1] = '\0'; // Null-terminate the checksum

    printf("Extracted URL: %s\n", extracted_url);
    printf("Original checksum (from device): %s\n", original_checksum);

    // Download the file from the extracted URL
    if (download_file(extracted_url, LOCAL_FILE_PATH) != 0) {
        fprintf(stderr, "Failed to download the file.\n");
        return;
    }
    printf("File downloaded successfully.\n");

    // Calculate the MD5 checksum of the downloaded file
    unsigned char md5_result[MD5_DIGEST_LENGTH];
    if (calculate_md5(LOCAL_FILE_PATH, md5_result) != 0) {
        fprintf(stderr, "Failed to calculate the checksum.\n");
        return;
    }

    // Convert the MD5 result to a hexadecimal string
    md5_to_hex(md5_result, file_url_checksum);
    printf("Calculated MD5 checksum of the file: %s\n", file_url_checksum);

    // Compare the calculated checksum with the checksum from the device
    if (strcmp(file_url_checksum, original_checksum) == 0) {
        printf("Checksum match! File integrity verified.\n");
    } else {
        printf("Checksum mismatch! File may be corrupted.\n");
    }
}

/**
 * Brief:
 * Downloads a file from a specified URL and saves it to a local path using libcurl.
 * 
 * Parameters:
 * - url: Pointer to a string representing the URL from which the file will be downloaded.
 * - local_path: Pointer to a string representing the local file path where the downloaded file will be saved.
 * 
 * Return:
 * - 0 on success, indicating the file was successfully downloaded.
 * - -1 on failure, such as if the URL initialization or file writing failed.
 */
int download_file(const char *url, const char *local_path) {
    CURL *curl;
    FILE *file;
    CURLcode res;

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize libcurl\n");
        return -1;
    }

    file = fopen(local_path, "wb");
    if (!file) {
        fprintf(stderr, "Failed to open file for writing: %s\n", local_path);
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "File download failed: %s\n", curl_easy_strerror(res));
        fclose(file);
        curl_easy_cleanup(curl);
        return -1;
    }

    fclose(file);
    curl_easy_cleanup(curl);
    return 0;
}


/**
 * Brief:
 * Calculates the MD5 checksum of a file and stores the result as a binary hash.
 * 
 * Parameters:
 * - file_path: Pointer to a string representing the path of the file 
 *              whose MD5 checksum is to be calculated.
 * - result: Pointer to an array where the 16-byte (128-bit) MD5 hash will 
 *           be stored. This array must be at least MD5_DIGEST_LENGTH (16 bytes) in size.
 * 
 * Return:
 * - 0 on success, indicating that the MD5 checksum was calculated and stored 
 *   in the `result` array.
 * - -1 on failure, such as if the file could not be opened.
 */
int calculate_md5(const char *file_path, unsigned char *result) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file for checksum calculation: %s\n", file_path);
        return -1;
    }

    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);

    unsigned char buffer[BUFFER_SIZE];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        MD5_Update(&md5_ctx, buffer, bytes);
    }

    MD5_Final(result, &md5_ctx);
    fclose(file);
    return 0;
}

/**
 * Brief:
 * Converts a binary MD5 hash into its hexadecimal string representation.
 * 
 * Parameters:
 * - md5: Pointer to the array containing the MD5 hash in binary format. 
 *        This array must have a length of MD5_DIGEST_LENGTH (16 bytes).
 * - hex: Pointer to a character array where the hexadecimal representation 
 *        of the MD5 hash will be stored. The size of this array must be 
 *        at least MD5_DIGEST_LENGTH * 2 + 1 (33 bytes) to hold the null-terminated string.
 * 
 * Return:
 * - This function does not return a value. The output is written directly 
 *   into the `hex` parameter.
 */
void md5_to_hex(const unsigned char *md5, char *hex) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(hex + (i * 2), "%02x", md5[i]);
    }
    hex[MD5_DIGEST_LENGTH * 2] = '\0'; // Null-terminate the string
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
    snprintf(ack_message, sizeof(ack_message), "File Downloaded successfully\n", DEVICE_ID, server_file_checksum,UPDATE_FIRMWARE_VERSION);
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
