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
 * Date: [Creation Date]
 * Version: 1.0
 */

#include "../include/file_transfer_utils.h"

char **selected_devices = NULL; //char array to store the selected devices ID
int selected_device_count = 0; //variable to handle number of selected devices
char *device_id;  // Buffer to hold device ID
pthread_mutex_t selected_devices_lock = PTHREAD_MUTEX_INITIALIZER;
#define MAX_SELECTED_DEVICES 10

char **acknowledgment_pending = NULL;  // List for acknowledgment pending
int num_acknowledgment_pending = 0;  // Counter for pending acknowledgments

/**
 * Brief:
 * Parse the SELECTED_CLIENTS environment variable and storing those values/ID in an array
 * Parses a comma-separated list of client identifiers and stores them
 * in the `selected_clients` array. This function modifies the input string `clients_str` by using `strtok`.
 * If the original string needs to remain unaltered, create a copy
 * before passing it to this function.
 *
 * parameters :
 * clients_str - A string containing comma-separated client identifiers.
 *               Example: "client1,client2,client3"
 * 
 * Return: NONE
 */

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
    num_acknowledgment_pending = 0;
    acknowledgment_pending = NULL;

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
 * 
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
    return 0;  // IP not in the list
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


