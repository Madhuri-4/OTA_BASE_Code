#include "../include/file_transfer_utils.h"

#include <errno.h>

char **selected_devices;
int selected_device_count = 0;
char *device_id;  // Buffer to hold device ID
#define MAX_SELECTED_DEVICES 10

/**
 * Brief:
 * Parse the SELECTED_CLIENTS environment variable and storing those values/ID in an array.
 * Parses a comma-separated list of client identifiers and stores them
 * in the `selected_devices` array. This function modifies the input string `clients_str` by using `strtok`.
 * If the original string needs to remain unaltered, create a copy
 * before passing it to this function.
 *
 * Parameters:
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
 * Checks if a given device ID is in the list of selected devices. If the ID is 
 * found, it returns `1`, indicating that the device is selected; otherwise, 
 * it returns `0`, indicating that the device is not selected.
 * 
 * Parameters:
 * device_id - The device ID to check.
 * 
 * Return: 1 if the device ID is found in the list of selected devices, 0 if not.
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

    // Iterate through the selected devices and check for a match
    for (int i = 0; i < selected_device_count; i++) {
        if (strcmp(selected_devices[i], device_id) == 0) {
            logger("DEBUG", "Device ID %s is selected.\n", device_id);
            return 1;  // Device ID found in the list
        }
    }

    logger("DEBUG", "Device ID %s is not in the selected list.\n", device_id);
    return 0;  // Device ID not found in the list
}

/**
 * Brief:
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


