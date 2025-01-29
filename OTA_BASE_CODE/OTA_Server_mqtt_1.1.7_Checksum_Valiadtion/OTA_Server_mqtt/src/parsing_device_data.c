/*
 * Copyright (c) 2025 Eximietas Design India Pvt. Ltd.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eximietas Design India Pvt. Ltd. 
 * proprietary license.
 *
 * File: parsing_device_data.c
 * Description:
 *    This file functionalities to manage and process a list of devices 
 *    selected for communication. It includes parsing device identifiers from 
 *    environment variables, checking if specific devices are in the list, and 
 *    a logging mechanism for debugging and monitoring.
 * 
 * Key Functionalities:
 *    - Parsing selected devices from environment variables.
 *    - Checking if a device ID is in the selected list.
 *    - Logging messages with timestamps and severity levels to a log file and console.
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
 * Author: Madhuri J M
 * Date: 15/01/2025
 * Version: 1.0
 */

#include "../include/file_transfer_utils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char **selected_devices = NULL; //char array to store the selected devices ID
int selected_device_count = 0; //variable to handle number of selected devices
char *device_id;  // Buffer to hold device ID
pthread_mutex_t selected_devices_lock = PTHREAD_MUTEX_INITIALIZER; // Mutex to protect access to the selected devices list.
#define MAX_SELECTED_DEVICES 30  // Maximum number of selected devices allowed.

#define AES_KEY_SIZE 256
#define RSA_KEY_SIZE 2048

#define AES_BLOCK_SIZE 16 

const char *firmware_file = "/home/navyasahiti/Server_failure_conditions_v1.4/OTA_Server_mqtt_1.4_latest/OTA_Server_mqtt_3/OTA_Server_mqtt/src/firmware_v1.0.bin";
const char *encrypted_file = "/home/navyasahiti/Server_failure_conditions_v1.4/OTA_Server_mqtt_1.4_latest/OTA_Server_mqtt_3/OTA_Server_mqtt/src/firmware_encrypted.bin";
const char *private_key_file = "private_key.pem";
const char *signature_file = "firmware_signature.sig";

// Function to encrypt firmware using AES
int encrypt_firmware(const char *input_file, const char *output_file, unsigned char *key, unsigned char *iv) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");

    if (!in || !out) {
        fprintf(stderr, "Error opening files for encryption.\n");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char buffer[1024], ciphertext[1040];
    int len, ciphertext_len;

    while ((len = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, buffer, len);
        fwrite(ciphertext, 1, ciphertext_len, out);
    }

    EVP_EncryptFinal_ex(ctx, ciphertext, &ciphertext_len);
    fwrite(ciphertext, 1, ciphertext_len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    printf("Firmware encrypted successfully.\n");
    return 0;
}

// Function to sign the encrypted firmware file
int sign_firmware(const char *data_file, const char *key_file, const char *signature_file) {
    FILE *key_fp = fopen(key_file, "r");
    if (!key_fp) {
        fprintf(stderr, "Unable to open private key file.\n");
        return -1;
    }

    RSA *rsa_key = PEM_read_RSAPrivateKey(key_fp, NULL, NULL, NULL);
    fclose(key_fp);

    FILE *data_fp = fopen(data_file, "rb");
    fseek(data_fp, 0, SEEK_END);
    long data_len = ftell(data_fp);
    rewind(data_fp);

    unsigned char *data = malloc(data_len);
    fread(data, 1, data_len, data_fp);
    fclose(data_fp);

    unsigned char signature[256];
    unsigned int sig_len;

    if (!RSA_sign(NID_sha256, data, data_len, signature, &sig_len, rsa_key)) {
        fprintf(stderr, "Error signing firmware.\n");
        RSA_free(rsa_key);
        free(data);
        return -1;
    }

    RSA_free(rsa_key);

    FILE *sig_fp = fopen(signature_file, "wb");
    fwrite(signature, 1, sig_len, sig_fp);
    fclose(sig_fp);

    free(data);
    printf("Firmware signed successfully.\n");
    return 0;
}

// Function to handle the encryption and signing logic
void handle_firmware_encryption_and_signing() {
    // Generate AES key and IV
    unsigned char aes_key[AES_KEY_SIZE / 8];
    unsigned char aes_iv[AES_BLOCK_SIZE];
    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(aes_iv, sizeof(aes_iv));

    // Encrypt the firmware file
    if (encrypt_firmware(firmware_file, encrypted_file, aes_key, aes_iv) != 0) {
        return;
    }

    // Sign the encrypted firmware
    if (sign_firmware(encrypted_file, private_key_file, signature_file) != 0) {
        return;
    }

    // The server code can then send these files (encrypted firmware and signature) over to the client.
}

void parse_selected_devices(const char *clients_str) {
    // Check for null input
    if (clients_str == NULL) {
        logger("ERROR", "Input string for clients is NULL.");//change the message
        return;
    }

    // Allocate memory for selected_devices
    selected_devices = (char**)malloc(selected_device_count * sizeof(char*));
    if (selected_devices == NULL) {
        logger("ERROR", "Memory allocation failed for selected_devices array.");
        perror("Error with malloc for selected_devices");  // Print system-level error
        exit(EXIT_FAILURE);  // Exit with failure status
    }

    // Create a copy of the clients_str to tokenize it without modifying the original string
    char *clients_str_copy = strdup(clients_str);
    if (clients_str_copy == NULL) {
        logger("ERROR", "Memory allocation failed for clients_str_copy.");
        perror("Error with strdup");  // Print system-level error
        free(selected_devices);  // Free allocated memory before returning
        exit(EXIT_FAILURE);  // Exit with failure status
    }

    // Tokenize the input string using commas as delimiters
    char *parsed_devices = strtok(clients_str_copy, ",");
    while (parsed_devices != NULL) {
        // Check if we are within the allocated space for selected_devices
        if (selected_device_count >= MAX_SELECTED_DEVICES) {  // Prevent overflow
            logger("ERROR", "Reached maximum device count. Cannot add more.");
            break;
        }

        // Allocate memory for each device ID
        selected_devices[selected_device_count] = (char *)malloc(10 * sizeof(char));  // Allocate space for each device ID
        if (selected_devices[selected_device_count] == NULL) {
            logger("ERROR", "Memory allocation failed for device %s.", parsed_devices);
            perror("Error with malloc for device");
            break;
        }

        // Copy the parsed device into the allocated space
        strcpy(selected_devices[selected_device_count], parsed_devices);

        // Increment the selected device count after successful addition
        selected_device_count++;
        parsed_devices = strtok(NULL, ",");
    }

    // If no devices were parsed, log an error
    if (selected_device_count == 0) {
        logger("ERROR", "No devices were parsed from the input string.");
    }

    // Free the copied string after use
    free(clients_str_copy);

    logger("INFO", "Parsed selected devices list from input string, stored in selected_devices[] array.");
}

/**
 * Brief:
 * This function clears the dynamically allocated memory for the selected devices,
 * resets the count of selected devices, clears acknowledgment tracking, and reloads
 * the selected devices.
 *
 * parameters : NONE
 * 
 * Return: NONE
 */
void reset_states() {
    pthread_mutex_lock(&selected_devices_lock);

    if (selected_devices) {
        for (int i = 0; i < selected_device_count; i++) {
            free(selected_devices[i]);  // Free each string
        }
        free(selected_devices);  // Free the array itself
    }

    selected_devices = NULL;
    selected_device_count = 0;

    logger("INFO", "Reset states for new devices.");

    pthread_mutex_unlock(&selected_devices_lock);

    // Reload selected devices
    load_selected_devices();
}

/**
 * Brief:
 * Loads the selected devices from the environment variable "SELECTED_DEVICES".
 * This function retrieves a comma-separated list of selected devices from an environment variable,
 * splits it into individual device names, and stores them in the `selected_devices` array.
 * It ensures thread safety using a mutex lock while modifying shared resources.
 *
 * parameters : NONE
 * 
 * Return: NONE
 */
void load_selected_devices() {
    const char *devices_env = getenv("SELECTED_DEVICES");
    
    if (devices_env == NULL || strlen(devices_env) == 0) {
        logger("INFO", "No selected devices found in environment variable.");
        return;
    }

    // Split the environment variable by commas
    char *devices_copy = strdup(devices_env);
    char *token = strtok(devices_copy, ",");
    
    pthread_mutex_lock(&selected_devices_lock);
    selected_device_count = 0;  // Reset previous list
    // Reallocate memory for the selected_devices array
    selected_devices = realloc(selected_devices, sizeof(char*) * MAX_CLIENTS);

    while (token != NULL && selected_device_count < MAX_CLIENTS) {
        selected_devices[selected_device_count++] = strdup(token);  // Store device
        token = strtok(NULL, ",");
    }
    pthread_mutex_unlock(&selected_devices_lock);

    logger("INFO", "Loaded selected devices.");
    free(devices_copy);
}
 
/**
 * Breif:
 * Checks if a given IP address is in the list of selected clients. If the IP is 
 * found, it returns `1`, indicating that the client is selected; otherwise, 
 * it returns `0`, indicating that the client is not selected.
 * 
 * Parameters:
 * ip - The IP address of the client to check.
 * 
 * Return: 1 if the IP is found in the list of selected clients, 0 if not.
 */
int is_device_selected(const char *device_id) {
    // Check for null input
    if (device_id == NULL) {
        logger("ERROR", "Device ID is NULL.");
        return 0;  // Device ID cannot be NULL
    }
    logger("DEBUG", "Checking device ID: %s\n", device_id);
    // If there are no selected devices, return 0
    if (selected_devices == NULL || selected_device_count == 0) {
        logger("ERROR", "No devices are selected.");
        return 0;
    }

    for (int i = 0; i < selected_device_count; i++) {
        if (strcmp(selected_devices[i], device_id) == 0) {
            logger("DEBUG", "Device ID %s is selected.\n", device_id);
            return 1;  // IP found in the list
        } 
    } 
    printf("Device ID %s is not in the selected list.\n", device_id); //facing issue when changed to logger    
        return 0;// IP not in the list  
}

/**
 * Breif:
 * This function calculates the MD5 hash of a given data buffer in memory.
 * It initializes an MD5 context, processes the input data, and returns the resulting MD5 hash.
 * 
 * Parameters:
 * data - Pointer to the input data whose MD5 hash needs to be calculated.
 * data_size - Size of the input data in bytes.
 * 
 * Return: Pointer to a dynamically allocated buffer containing the MD5 hash (16 bytes).
 */
unsigned char* calculate_md5_from_memory(const unsigned char *data, size_t data_size) {
    MD5_CTX md5_ctx;
    unsigned char *md5_hash = (unsigned char*)malloc(MD5_DIGEST_LENGTH);

    if (md5_hash == NULL) {
        return NULL;  // Memory allocation failed
    }

    MD5_Init(&md5_ctx);
    MD5_Update(&md5_ctx, data, data_size);
    MD5_Final(md5_hash, &md5_ctx);

    return md5_hash;
}

/**
 * Breif:
 * Callback function for handling data received via libcurl.
 * This function is called by libcurl when data is received from the server.
 * It copies the received data into the provided buffer.
 * 
 * Parameters:
 * ptr - Pointer to the received data.
 * size - Size of each data element.
 * nmemb - Number of data elements.
 * data - Pointer to a user-provided buffer where the data will be stored.
 * 
 * Return: The number of bytes successfully copied (size * nmemb).
 */
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *data) {
    size_t total_size = size * nmemb;
    unsigned char *buffer = (unsigned char *)data;

    // Update total data size
    total_data_size += total_size;

    // Copy data to buffer
    memcpy(buffer + total_data_size - total_size, ptr, total_size);

    return total_size;
}

/**
 * Breif:
 * Fetches a file from the given URL and calculates its MD5 checksum.
 * This function uses libcurl to download a file from the specified URL and then
 * computes its MD5 checksum.
 * 
 * Parameters:
 * url - The URL of the .bin file.
 * 
 * Return: 0 on success, 1 on failure
 */
int fetch_and_calculate_checksum(const char *file) {
    CURL *curl;
    CURLcode res;
    unsigned char buffer[DOWNLOAD_BUFFER_SIZE];

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        curl_global_cleanup();
        return 1;
    }

    // Set curl options to fetch the file from the URL
    curl_easy_setopt(curl, CURLOPT_URL, file);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);

    // Perform the download
    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    // Calculate checksum of the downloaded data
    unsigned char *md5_hash = calculate_md5_from_memory(buffer, total_data_size);
    if (md5_hash) {
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            sprintf(&server_checksum[i * 2], "%02x", md5_hash[i]);
        }
        server_checksum[MD5_DIGEST_LENGTH * 2] = '\0';
        printf("MD5 checksum for file %s: %s\n", file, server_checksum);
        free(md5_hash);
    } else {
        fprintf(stderr, "Failed to calculate MD5 checksum.\n");
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
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
    static int is_first_call = 1; // Flag to check if this is the first call

    // On first call, open file in "w" mode to clear previous content
    FILE *log_file = fopen(LOG_FILE, is_first_call ? "w" : "a");
    if (!log_file) {
        fprintf(stderr, "[ERROR] Unable to open log file for writing.\n");
        return;
    }
    is_first_call = 0; // After first call, use append mode for subsequent calls

    // Get current time
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // Format timestamp
    char timestamp[64];
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);

    // Print log to console
    printf("[%s] [%s] ", timestamp, level);

    // Write log to file
    fprintf(log_file, "[%s] [%s] ", timestamp, level);

    // Handle variable arguments
    va_list args;
    va_start(args, format);
    vprintf(format, args);               // Print to console
    vfprintf(log_file, format, args);    // Write to file
    va_end(args);

    // Add newlines
    printf("\n");
    fprintf(log_file, "\n");

    fclose(log_file);
}


