

/*
 * Copyright (c) 2025 Eximietas Design India Pvt. Ltd.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eximietas Design India Pvt. Ltd. 
 * proprietary license.
 *
 * File: exim_library_mqtt.c
 * Description:
 *    This file contains a collection of wrapper functions built around the Mosquitto MQTT library.
 *    It provides utility methods for MQTT initialization, connection, and cleanup, along with 
 *    advanced features such as TLS configuration and username/password authentication.
 * 
 * Key Functionalities:
 *    - Initializes and cleans up Mosquitto library resources.
 *    - Creates Mosquitto client instances for MQTT communication.
 *    - Handles MQTT authentication using username and password.
 *    - Configures TLS/SSL settings for secure communication.
 *    - Manages connection to an MQTT broker, including error handling.
 *    - Provides custom callbacks for MQTT events such as connection establishment.
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
#include <pthread.h>


 
/**
 * Breif:
 * Initializes the Mosquitto library. This function calls `mosquitto_lib_init` to initialize the Mosquitto library,
 * 
 * This initialization sets up internal resources and prepares the library for subsequent operations, 
 * such as connecting to a broker, subscribing to topics, or publishing messages.
 * 
 * Parameters: NONE
 * 
 * Return: NONE
 */
void exim_mosquitto_lib_init() {
    int result = mosquitto_lib_init();
    if(result == MOSQ_ERR_SUCCESS) {
        logger("INFO", "mosquitto_lib_init: Success\n");
    } else {
        logger("ERROR", "mosquitto_lib_init: Failed with error code %d\n", result);
    }
}

/**
 * Breif:
 * Creates a new Mosquitto client instance, that can be used for MQTT communication, 
 * such as connecting to a broker, subscribing to topics, or publishing messages.
 * 
 * Parameters: 
 * id - A string representing the client ID. Must be unique per broker.
 *      If `NULL`, the library generates a random ID (if `clean_session` is true).
 * clean_session - A boolean indicating whether to start with a clean session.
 *                 `true` clears all session data on disconnection; `false` retains it.
 * userdata - A pointer to custom user-defined data that can be accessed in callbacks.
 * 
 * Return - A pointer to the created `struct mosquitto` object if successful, or `NULL` if failed.
 *
 */
struct mosquitto* exim_mosquitto_new(const char *id, bool clean_session, void *userdata) {
    struct mosquitto *mosq = mosquitto_new(id, clean_session, userdata);
    if(mosq != NULL) {
        logger("INFO", "mosquitto_new: Success\n");
    } else {
        logger("INFO", "mosquitto_new: Failed\n");
    }
    return mosq;
}



/*
 * Breif:
 * function Handles actions upon successful or failed connection to the MQTT broker,
 *        including subscribing to a specific topic and publishing client version metadata.
 *
 * parameters :
 * mosq      - Pointer to the MQTT client instance that will connect to the broker.
 * host      - The hostname or IP address of the MQTT broker.
 * port      - The port number on which the MQTT broker is listening (1883 or 8883).
 * keepalive - This is the maximum time interval in seconds between messages sent or received.
 *
 * Return : Integer indicating the result of the connect operation
 * 
*/
int exim_mosquitto_connect(struct mosquitto *mosq, const char *host, int port, int keepalive) {
    int attempt = 0;
    if (mosq == NULL || host == NULL) {
        logger("ERROR", "exim_mosquitto_connect: Invalid parameter(s), mosq or host is NULL.\n");
        return MOSQ_ERR_INVAL; // Return an error code for invalid parameters
    }
    while (attempt < MAX_RETRIES) {
        int result = mosquitto_connect(mosq, host, port, keepalive);
        if (result == MOSQ_ERR_SUCCESS) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Successfully connected to broker\n");
            logger("INFO", msg);  // Log info level message
            return result;
        } else {
            // Log the failure case with appropriate error handling
            switch (result) {
                case MOSQ_ERR_ERRNO:
                    logger("ERROR", "Connection failed: MOSQ_ERR_ERRNO (System error, errno set)\n");
                    break;
                case MOSQ_ERR_NOMEM:
                    logger("ERROR", "Connection failed: MOSQ_ERR_NOMEM (Out of memory)\n");
                    break;
                case MOSQ_ERR_PROTOCOL:
                    logger("ERROR", "Connection failed: MOSQ_ERR_PROTOCOL (Protocol error, version mismatch?)\n");
                    break;
                case MOSQ_ERR_INVAL:
                    logger("ERROR", "Connection failed: MOSQ_ERR_INVAL (Invalid parameters)\n");
                    break;
                case MOSQ_ERR_UNKNOWN:
                    logger("ERROR", "Connection failed: MOSQ_ERR_UNKNOWN (Unknown error)\n");
                    break;
                case MOSQ_ERR_PROXY:
                    logger("ERROR", "Connection failed: MOSQ_ERR_PROXY (Proxy error)\n");
                    break;
                case MOSQ_ERR_CONN_REFUSED:
                    logger("ERROR", "Connection failed: MOSQ_ERR_CONN_REFUSED (Connection refused by the broker)\n");
                    break;
                case MOSQ_ERR_CONN_LOST:
                    logger("ERROR", "Connection lost: MOSQ_ERR_CONN_LOST (Connection lost after connection)\n");
                    break;
                case MOSQ_ERR_TLS:
                    logger("ERROR", "Connection failed: MOSQ_ERR_TLS (TLS/SSL error)\n");
                    break;
                case MOSQ_ERR_MALFORMED_UTF8:
                    logger("ERROR", "Connection failed: MOSQ_ERR_MALFORMED_UTF8 (Malformed message format)\n");
                    break;
                default:
                    char msg[100];
                    snprintf(msg, sizeof(msg), "Connection failed with an unknown error code: %d\n", result);
                    logger("ERROR", msg);
                    break;
            }
            logger("WARNING", " Please verify the broker address, credentials, and network connection\n.");
            logger("INFO", " Retrying in %d seconds... (Attempt %d/%d)\n", RECONNECT_DELAY, attempt + 1, MAX_RETRIES);
            mosquitto_disconnect(mosq);  // Ensure cleanup before retry
            sleep(RECONNECT_DELAY);
            attempt++;
            
        }
        
    }
     // Exit if all retries fail
    logger("ERROR", "Failed to connect after %d attempts. Exiting.\n", MAX_RETRIES);
    exim_mosquitto_destroy(mosq);
    exim_mosquitto_lib_cleanup();
    exit(0);
    return MOSQ_ERR_CONN_REFUSED;  // Return appropriate failure code

    //return result; // Return the connection result
}


/**
 * Breif:
 * Cleans up and releases resources associated with a Mosquitto client instance.
 * ensuring that all memory and resources allocated for the Mosquitto client are 
 * properly freed.
 * 
 * Parameters:
 * mosq - A pointer to the Mosquitto client instance to be destroyed.
 * 
 * Return: NONE
 */
void exim_mosquitto_destroy(struct mosquitto *mosq) {
    mosquitto_destroy(mosq);
    exim_mosquitto_lib_cleanup();
    logger("INFO", "mosquitto_destroy: Success\n");
}


/**
 * Breif:
 * Cleans up and releases resources used by the Mosquitto library.
 * ensuring that all internal library resources, such as memory and networking handles, 
 * are properly freed when the Mosquitto client is no longer needed.
 * 
 * Parameters: NONE
 * 
 * Return: NONE
 */
void exim_mosquitto_lib_cleanup() {
    mosquitto_lib_cleanup();
    logger("INFO", "mosquitto_lib_cleanup: Success\n");
}

/*
 * Breif:
 * function Handles actions upon successful or failed connection to the MQTT broker,
 *        including subscribing to a specific topic and publishing client version metadata.
 *
 * parameters :
 * mosq - Pointer to the MQTT client instance.
 * userdata - User-defined data passed to the callback.
 * rc - Return code indicating the connection status (0 for success, non-zero for failure).
 *
 * Return : None
 * 
*/
void exim_on_connect(struct mosquitto *mosq, void *userdata, int rc) {
   if (rc == 0) {
     logger("INFO", "On Connect succuesfull!\n");

     // Subscribe to the transfer topic for this client
        char read_file[256];
        snprintf(read_file, sizeof(read_file), FILE_TRANSFER_TOPIC); //facing issue when changed to logger
        exim_mosquitto_subscribe(mosq, NULL, read_file, 0);
        printf("Subscribed to topic: %s\n", read_file); //facing issue when changed to logger

        // Send the client version to the server
        char payload[256];
        snprintf(payload, sizeof(payload), "%s:%s", DEVICE_ID, FIRMWARE_VERSION); //facing issue when changed to logger

    // Start a thread for periodic publishing
    pthread_t publish_thread;
    pthread_create(&publish_thread, NULL, exim_periodic_publish, mosq);
        
   }
    else 
    {
        
        // Connection failed, log detailed error message based on rc
        switch (rc) {
            case 1:
                logger("ERROR", "Connection failed: Incorrect protocol version\n");
                break;
            case 2:
                logger("ERROR", "Connection failed: Invalid client identifier\n");
                break;
            case 3:
                logger("ERROR", "Connection failed: Server unavailable\n");
                break;
            case 4:
                logger("ERROR", "Connection failed: Bad username or password\n");
                break;
            case 5:
                logger("ERROR", "Connection failed: Not authorized\n");
                break;
            default:
                logger("ERROR", "Connection failed with error code: %d\n", rc);
                break;
        }
    }
        
}

/**
 * Breif:
 * This function acts as a wrapper around the `mosquitto_username_pw_set` function. 
 * It sets the username and password to be used when connecting to the MQTT broker. 
 * The function logs the result of the operation, indicating whether it succeeded or failed.
 * 
 * Parameters: 
 * mosq     - A pointer to a valid `mosquitto` instance.
 * username - The username for authentication. Pass `NULL` if no username is required.
 * password - The password for authentication. Pass `NULL` if no password is required.
 * 
 * Return - `MOSQ_ERR_SUCCESS` (0) on success.
 *        - `MOSQ_ERR_INVAL`: Invalid parameters (e.g., `mosq` is NULL).
 *        - `MOSQ_ERR_NOMEM`: Out of memory.
 */
int exim_mosquitto_username_pw_set(struct mosquitto *mosq, const char *username, const char *password) {
    int rc = mosquitto_username_pw_set(mosq, username, password);
    if(rc == MOSQ_ERR_SUCCESS) {
        logger("INFO", "mosquitto_username_pw_set: Success\n");
    } else {
        logger("ERROR", "mosquitto_username_pw_set: Failed with error code %d\n", rc);
    }
    return rc;
}

/**
 * Breif:
 * This function acts as a wrapper around the `mosquitto_tls_set` function. 
 * It configures the TLS/SSL settings for the Mosquitto client, such as the CA certificate, 
 * certificate path, client certificate, and private key.
 * 
 * Parameters: 
 * mosq     - A pointer to a valid `mosquitto` instance.
 * cafile   - Path to the file containing the PEM-encoded CA certificate. 
 * capath   - Path to a directory containing the CA certificates in PEM format. 
 * cerfile  - Path to the client certificate file in PEM format.
 * keyfile  - Path to the private key file in PEM format. 
 * password - Password for the private key file, if encrypted. 
 * 
 * Return - `MOSQ_ERR_SUCCESS` (0) on success.
 *        - `MOSQ_ERR_INVAL`: Invalid parameters (e.g., `mosq` is NULL).
 *        - `MOSQ_ERR_NOMEM`: Out of memory.
 *        - `MOSQ_ERR_TLS`: TLS setup failed.
 *
 */
int exim_mosquitto_tls_set(struct mosquitto *mosq, const char *cafile, const char*capath, const char*cerfile, const char*keyfile, const char*password) {
    int rc = mosquitto_tls_set(mosq, cafile, capath, cerfile, keyfile, NULL);
    if(rc == MOSQ_ERR_SUCCESS) {
        logger("INFO", "mosquitto_tls_set: Success\n");
    } else {
        logger("ERROR", "mosquitto_tls_set: Failed with error code %d\n", rc);
    }
    return rc;
}



/**
 * Breif: 
 * Callback function for handling incoming messages on subscribed topics.
 * It processes the message based on the topic it was published to, parsing the payload 
 * and taking appropriate actions (such as sending a file or logging an acknowledgment).
 * 
 * Parameters:
 * mosq - The Mosquitto client object.
 * userdata - User-defined data passed to the callback.
 * message - The message object containing the topic, payload, and additional details.
 * 
 * Return: NONE
 * 
 */
void exim_on_message(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message) {
    if (message->payloadlen > 0) {
        save_received_file(message->payload, message->payloadlen);
        
        // Send acknowledgment to the server
        send_acknowledgment(mosq);
    }
}

/**
 * Breif:
 * Sets a callback function to handle MQTT connection events.
 * 
 * Parameters:
 * mosq - A pointer to the initialized Mosquitto client instance.
 * on_connect - A pointer to the callback function to handle connection events.
 * 
 * Return: NONE
 */
void exim_mosquitto_connect_callback_set(struct mosquitto *mosq, void (*on_connect)(struct mosquitto *, void *, int)) {
    mosquitto_connect_callback_set(mosq, on_connect);
   logger("INFO", "mosquitto_connect_callback_set: Success\n");
}


/**
 * Breif:
 * Sets a callback function to handle incoming MQTT messages.
 * 
 * Parameters:
 * mosq - A pointer to the initialized Mosquitto client instance.
 * on_message - A pointer to the callback function to handle incoming messages.
 * 
 * Return: NONE
 *  
 */
void exim_mosquitto_message_callback_set(struct mosquitto *mosq, void (*on_message)(struct mosquitto *, void *, const struct mosquitto_message *)) {
    mosquitto_message_callback_set(mosq, on_message);
    logger("INFO", "mosquitto_message_callback_set: Success\n");
}


/**
 * Breif:
 * Wrapper function for subscribing to an MQTT topic using the Mosquitto library.
 * This function subscribes to a specific topic with the specified quality of service (QoS0) level.
 * 
 * Parameters:
 * mosq - The Mosquitto client object.
 * mid - Pointer to the message ID for the subscription. This can be NULL if not needed.
 * sub - The topic to subscribe to.
 * qos - The quality of service level for the subscription (0, 1, or 2).
 * 
 * Return: result of the `mosquitto_subscribe` function call (0 for success, non-zero for failure).
 */
int exim_mosquitto_subscribe(struct mosquitto *mosq, int *mid, const char *sub, int qos) {
    int result = mosquitto_subscribe(mosq, mid, sub, qos);
    if(result == MOSQ_ERR_SUCCESS) {
        logger("INFO", "mosquitto_subscribe: Success\n");
    } else {
        logger("ERROR", "mosquitto_subscribe: Failed with error code %d\n", result);
    }
    return result;
}

/**
 * Breif:
 * Starts an event loop for the Mosquitto client that runs indefinitely.
 * ensures the client remains connected to the broker until an error occurs or the loop is terminated.
 * 
 * Parameters:
 * mosq - A pointer to the initialized Mosquitto client instance.
 * timeout - Maximum number of milliseconds to wait for network activity 
 *           before performing periodic maintenance tasks.
 * max_packets - Maximum number of messages to process per iteration.
 * 
 * Return: Returns `MOSQ_ERR_SUCCESS` (0) on success, or an error code on failure
 */
int exim_mosquitto_loop_forever(struct mosquitto *mosq, int timeout, int max_packets) {
    int result = mosquitto_loop_forever(mosq, timeout, max_packets);
    if(result == MOSQ_ERR_SUCCESS) {
        logger("INFO", "mosquitto_loop_forever: Success\n");
    } else {
        logger("ERROR", "mosquitto_loop_forever: Failed with error code %d\n", result);

    }

    return result;
}

// Custom wrapper function for Mosquitto publish
int exim_mosquitto_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain) {
        // Call the Mosquitto library's publish function
    int result = mosquitto_publish(mosq, mid, topic, payloadlen, payload, qos, retain);
    // Log the input parameters
    printf("Preparing to publish:\n"); //facing issue when changed to logger
    printf( "Topic: %s\n", topic); //facing issue when changed to logger
    printf("Payload: %.*s\n", payloadlen, (const char *)payload); //facing issue when changed to logger
  
    // Log the result of the publish call
    if (result == MOSQ_ERR_SUCCESS) {
        logger("INFO","mosquitto_publish: Success\n");
    } else {
        logger("ERROR","mosquitto_publish: Failed with error code %d\n", result);
    }

    return result;
}

// Custom wrapper function for Periodic publish
void* exim_periodic_publish(void *arg) {
    // Cast the input argument to a Mosquitto client instance pointer
    struct mosquitto *mosq = (struct mosquitto *)arg;

    // Declare a character array to store the payload to be published
    char payload[256];

    // Format the payload string with the device ID and firmware version
    snprintf(payload, sizeof(payload), "%s:%s", DEVICE_ID, FIRMWARE_VERSION);

    // Enter an infinite loop to periodically publish messages
    while (1) {
        // Publish the message to the MQTT broker on the "device/info" topic
        exim_mosquitto_publish(mosq, NULL, "device/info", strlen(payload), payload, 0, false);

        // Log a message indicating that the periodic message has been published
        logger("INFO", "Periodic message published.\n");

        // Pause the loop execution for 5 seconds before publishing the next message
        sleep(5);
    }

    // Return NULL to indicate the thread has completed (this won't be reached due to the infinite loop)
    return NULL;
}

