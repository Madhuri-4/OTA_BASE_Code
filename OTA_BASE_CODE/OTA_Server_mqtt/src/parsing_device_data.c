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

char **selected_devices;
int selected_device_count = 0;
char *device_id;  // Buffer to hold device ID

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
    selected_devices = (char**)malloc(selected_device_count*sizeof(char*));
    if (selected_devices == NULL) {
        printf("Memory allocation failed.\n");
        EXIT_FAILURE;
    }
    char *parsed_devices = strtok((char *)clients_str, ",");
    while (parsed_devices != NULL) {
        selected_devices[selected_device_count] = (char *)malloc(10 * sizeof(char));
        strcpy(selected_devices[selected_device_count],parsed_devices);
        selected_device_count++;
        parsed_devices = strtok(NULL, ",");
    }
    logger("INFO", "Parsed selected device list from getenv, stored in selected_devices[] array\n");
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
    logger("DEBUG", "Checking device ID: %s\n", device_id);
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

    // Add newlines
    printf("\n");
    fprintf(log_file, "\n");

    fclose(log_file);
}


