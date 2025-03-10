#include "../include/exim_mqtt.h"
#include "../include/file_transfer_utils.h"

const char *file_path = "/OTA/Delta_packages/firmware_v1.1.bin"; // File path to store the send the update file to devices

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
        exim_mosquitto_publish(mosq, NULL, topic, bytes_read, buffer, 0, false);
    }

    fclose(file);
    //printf("Bin file sent successfully to %s\n", ip); //getting issue when changed to logger
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
         logger("ERROR", "SELECTED_CLIENTS environment variable not set.\n");
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
    
    // Clean up
    exim_mosquitto_destroy(mosq);
    exim_mosquitto_lib_cleanup();

    return 0;
}
