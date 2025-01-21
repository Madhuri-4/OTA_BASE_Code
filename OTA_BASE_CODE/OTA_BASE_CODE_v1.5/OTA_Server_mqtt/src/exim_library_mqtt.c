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
 * Author: Madhuri J M
 * Date: [Creation Date]
 * Version: 1.0
 */

#include "../include/exim_mqtt.h"
#include "../include/file_transfer_utils.h"

/**
 * Breif:
 * Initializes the Mosquitto library. This function calls `mosquitto_lib_init` to initialize the Mosquitto library,
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
        logger("ERROR", "mosquitto_lib_init: Failed with error code %d, %s\n", result, strerror(errno));
    }
}

/**
 * Breif:
 * Creates a new Mosquitto client instance, that can be used for MQTT communication, 
 * such as connecting to a broker, subscribing to topics, or publishing messages.
 * 
 * Parameters: 
 * id            - A string representing the client ID. Must be unique per broker.
 *                 If `NULL`, the library generates a random ID (if `clean_session` is true).
 * clean_session - A boolean indicating whether to start with a clean session.
 *                 `true` clears all session data on disconnection; `false` retains it.
 * userdata      - A pointer to custom user-defined data that can be accessed in callbacks.
 * 
 * Return - A pointer to the created `struct mosquitto` object if successful, or `NULL` if failed.
 *
 */
struct mosquitto* exim_mosquitto_new(const char *id, bool clean_session, void *userdata) {
    struct mosquitto *mosq = mosquitto_new(id, clean_session, userdata);
    if(mosq == NULL) {
        logger("ERROR", "mosquitto_new: Failed with error %s\n", strerror(errno));
    } else {
        logger("INFO", "mosquitto_new: Success\n");
    }
    return mosq;
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
    if(mosq == NULL) {
        logger("ERROR", "exim_mosquitto_username_pw_set: mosq is NULL.\n");
        return MOSQ_ERR_INVAL;
    }

    int rc = mosquitto_username_pw_set(mosq, username, password);
    if(rc == MOSQ_ERR_SUCCESS) {
        logger("INFO", "mosquitto_username_pw_set: Success\n");
    } else {
        logger("ERROR", "mosquitto_username_pw_set: Failed with error code %d, %s\n", rc, strerror(errno));
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
int exim_mosquitto_tls_set(struct mosquitto *mosq, const char *cafile, const char* capath, const char* cerfile, const char* keyfile, const char* password) {
    if(mosq == NULL) {
        logger("ERROR", "exim_mosquitto_tls_set: mosq is NULL.\n");
        return MOSQ_ERR_INVAL;
    }

    // Check for cafile existence and readability
    if(cafile != NULL) {
        FILE *file = fopen(cafile, "r");
        if (file == NULL) {
            logger("ERROR", "exim_mosquitto_tls_set: Cannot read cafile %s, error: %s\n", cafile, strerror(errno));
            return MOSQ_ERR_TLS;  // Return TLS error if the file cannot be opened
        } else {
            fclose(file);  // Close the file if it exists and can be opened
        }
    } else {
        logger("ERROR", "exim_mosquitto_tls_set: cafile is NULL.\n");
        return MOSQ_ERR_TLS;  // Return TLS error if cafile is NULL
    }

    // Log input parameters for debugging
    logger("INFO", "exim_mosquitto_tls_set: cafile = %s, capath = %s, cerfile = %s, keyfile = %s\n", 
           cafile ? cafile : "NULL", 
           capath ? capath : "NULL", 
           cerfile ? cerfile : "NULL", 
           keyfile ? keyfile : "NULL");

    // Perform TLS set
    int rc = mosquitto_tls_set(mosq, cafile, capath, cerfile, keyfile, NULL);
    if(rc == MOSQ_ERR_SUCCESS) {
        logger("INFO", "mosquitto_tls_set: Success\n");
    } else {
        logger("ERROR", "mosquitto_tls_set: Failed with error code %d, %s\n", rc, strerror(errno));
    }

    return rc;
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
                    logger("ERROR", "Connection failed: MOSQ_ERR_ERRNO (System error, errno set)");
                    break;
                case MOSQ_ERR_NOMEM:
                    logger("ERROR", "Connection failed: MOSQ_ERR_NOMEM (Out of memory)");
                    break;
                case MOSQ_ERR_PROTOCOL:
                    logger("ERROR", "Connection failed: MOSQ_ERR_PROTOCOL (Protocol error, version mismatch?)");
                    break;
                case MOSQ_ERR_INVAL:
                    logger("ERROR", "Connection failed: MOSQ_ERR_INVAL (Invalid parameters)");
                    break;
                case MOSQ_ERR_UNKNOWN:
                    logger("ERROR", "Connection failed: MOSQ_ERR_UNKNOWN (Unknown error)");
                    break;
                case MOSQ_ERR_PROXY:
                    logger("ERROR", "Connection failed: MOSQ_ERR_PROXY (Proxy error)");
                    break;
                case MOSQ_ERR_CONN_REFUSED:
                    logger("ERROR", "Connection failed: MOSQ_ERR_CONN_REFUSED (Connection refused by the broker)");
                    break;
                case MOSQ_ERR_CONN_LOST:
                    logger("ERROR", "Connection lost: MOSQ_ERR_CONN_LOST (Connection lost after connection)");
                    break;
                case MOSQ_ERR_TLS:
                    logger("ERROR", "Connection failed: MOSQ_ERR_TLS (TLS/SSL error)");
                    break;
                case MOSQ_ERR_MALFORMED_UTF8:
                    logger("ERROR", "Connection failed: MOSQ_ERR_MALFORMED_UTF8 (Malformed message format)");
                    break;
                default:
                    char msg[100];
                    snprintf(msg, sizeof(msg), "Connection failed with an unknown error code: %d", result);
                    logger("ERROR", msg);
                    break;
            }
            logger("WARNING", "Please verify the broker address, credentials, and network connection.");
            logger("INFO", "Retrying in %d seconds... (Attempt %d/%d)\n", RECONNECT_DELAY, attempt + 1, MAX_RETRIES);
            mosquitto_disconnect(mosq);  // Ensure cleanup before retry
            sleep(RECONNECT_DELAY);
            attempt++;
        }
        
    }
     // Exit if all retries fail
    logger("ERROR", "Failed to connect after %d attempts. Exiting.", MAX_RETRIES);
    exim_mosquitto_destroy(mosq);
    exim_mosquitto_lib_cleanup();
    
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
    if (mosq == NULL) {
        logger("ERROR", "exim_mosquitto_destroy: mosq is NULL.\n");
        return;
    }
    free(selected_devices);
    free(device_id);
    mosquitto_destroy(mosq);
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
    int result = mosquitto_lib_cleanup();
    if (result == MOSQ_ERR_SUCCESS) {
        logger("INFO", "mosquitto_lib_cleanup: Success\n");
    } else {
        logger("ERROR", "mosquitto_lib_cleanup: Failed with error code %d\n", result);
    }
}

/*
 * Breif:
 * function Handles actions upon successful or failed connection to the MQTT broker,
 *        including subscribing to a specific topic and publishing client version metadata.
 *
 * parameters :
 * mosq     - Pointer to the MQTT client instance.
 * userdata - User-defined data passed to the callback.
 * rc       - Return code indicating the connection status (0 for success, non-zero for failure).
 *
 * Return : None
 * 
*/
void exim_on_connect(struct mosquitto *mosq, void *userdata, int rc) {
    if (rc == 0) {
        // Connection successful
        exim_mosquitto_subscribe(mosq, NULL, TOPIC_DEVICE_VERSION, 0);  // Subscribe to version topic
        exim_mosquitto_subscribe(mosq, NULL, TOPIC_DEVICE_ACK, 0);      // Subscribe to ack topic
    } else {
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
 * Callback function for handling incoming messages on subscribed topics.
 * It processes the message based on the topic it was published to, parsing the payload 
 * and taking appropriate actions (such as sending a file or logging an acknowledgment).
 * 
 * Parameters:
 * mosq     - The Mosquitto client object.
 * userdata - User-defined data passed to the callback.
 * message  - The message object containing the topic, payload, and additional details.
 * 
 * Return: NONE
 * 
 */

void exim_on_message(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message) {
    if (message->payloadlen > 0) {
        //printf("Received message on topic %s: %s\n", message->topic, (char *)message->payload);
        logger("INFO", "Received message on topic %s: %s\n", message->topic, (char *)message->payload);

        // Check if the message is from the TOPIC_DEVICE_VERSION topic
        if (strcmp(message->topic, TOPIC_DEVICE_VERSION) == 0) {
            // Parse the IP address and version from the payload
            char *version;    // Buffer to hold version string
            device_id = (char *)malloc(256 * sizeof(char));
            version = (char *)malloc(256 * sizeof(char));
            if (!device_id || !version) {
                logger("ERROR", "Memory allocation failed\n");
                free(device_id); free(version);
                return;
            }
            // Extracts the client IP address (up to 99 characters) and version number (integer) from the payload string.
            if (sscanf((char *)message->payload, "%255[^:]:%255s", device_id, version) == 2) {
                printf("Device ID: %s\n", device_id);
                if (is_device_selected(device_id)) {
                    //logger("INFO", "Device ID %s selected, sending file.\n", device_id);
                    send_file_in_bytes(mosq, file_path, device_id);
                    //logger("INFO", "File sending attempt made for device %s.\n", device_id);
                } else {
                    printf("Device ID %s not selected, ignoring transfer.\n", device_id); //facing issue when changed to logger
                }
            } else {
                logger("ERROR", "Failed to parse version information from payload.");
            }
            //free the allocated memory
            free(device_id);
            free(version);
        }

        // Handle acknowledgment from the subscriber(device)
        else if (strncmp(message->topic, TOPIC_DEVICE_ACK, strlen(TOPIC_DEVICE_ACK)) == 0) {
            //printf("Acknowledgment received: %s\n", (char *)message->payload);//- when used logger facing issue
            char device_checksum[MD5_DIGEST_LENGTH * 2 + 1];
            if(sscanf((char *)message->payload, "Device ID:%255s Device checksum: %64[^,]", device_id, device_checksum) == 2) {
                device_checksum[MD5_DIGEST_LENGTH * 2] = '\0';
                //printf("Parsed Device ID: %s, Parsed Checksum: %s\n", device_id, device_checksum); //- when used logger facing issue
                // Compare checksums
                if (strcmp(server_checksum, device_checksum) == 0) {
                    logger("INFO", "Device received file successful. Checksum matches.");
                    reset_states();
                    load_selected_devices();
                } else {
                    logger("ERROR", "Device not received file, failed. Checksum does not match.");
                }
            } else {
                logger("DEBUG", "Acknowledgment from device is NULL\n");
            }
        }
    }
}

/**
 * Breif:
 * Sets a callback function to handle MQTT connection events.
 * 
 * Parameters:
 * mosq       - A pointer to the initialized Mosquitto client instance.
 * on_connect - A pointer to the callback function to handle connection events.
 * 
 * Return: NONE
 */
void exim_mosquitto_connect_callback_set(struct mosquitto *mosq, void (*on_connect)(struct mosquitto *, void *, int)) {
    if (mosq == NULL || on_connect == NULL) {
        logger("ERROR", "exim_mosquitto_connect_callback_set: Invalid parameter(s), mosq or on_connect is NULL.\n");
        return;
    }

    mosquitto_connect_callback_set(mosq, on_connect);
    logger("INFO", "mosquitto_connect_callback_set: Success\n");
}


/**
 * Breif:
 * Sets a callback function to handle incoming MQTT messages.
 * 
 * Parameters:
 * mosq       - A pointer to the initialized Mosquitto client instance.
 * on_message - A pointer to the callback function to handle incoming messages.
 * 
 * Return: NONE
 *  
 */
void exim_mosquitto_message_callback_set(struct mosquitto *mosq, void (*on_message)(struct mosquitto *, void *, const struct mosquitto_message *)) {
    if (mosq == NULL || on_message == NULL) {
        logger("ERROR", "exim_mosquitto_message_callback_set: Invalid parameter(s), mosq or on_message is NULL.\n");
        return;
    }

    mosquitto_message_callback_set(mosq, on_message);
    logger("INFO", "mosquitto_message_callback_set: Success\n");
}

/**
 * Breif:
 * The function exim_mosquitto_publish is a wrapper around the Mosquitto MQTT client's mosquitto_publish function. 
 * It is used to publish a message to a specific MQTT topic with the given quality of service (QoS) level and retain flag. 
 * 
 * Parameters:
 * mosq       - Pointer to the Mosquitto client instance that is publishing the message.
 * mid        -  Pointer to an integer to store the message ID, or NULL if not required.
 * topic      - The MQTT topic to which the message is to be published.
 * payloadlen - The length of the payload in bytes. It should match the size of the payload.
 * payload    - Pointer to the message payload to be sent.
 * qos        - Quality of Service level for the message.
 * retain     - Boolean flag indicating whether the message should be retained on the broker:
 *              true - The broker retains the message for future subscribers to the topic.
 *              false - The message is not retained on the broker.
 * 
 * Return: Integer indicating the result of the publish operation
 * 
 */
int exim_mosquitto_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain) {
    if (mosq == NULL) {
        logger("ERROR", "exim_mosquitto_publish: Invalid parameter, mosq is NULL.\n");
        return MOSQ_ERR_INVAL;
    }

    if (topic == NULL) {
        logger("ERROR", "exim_mosquitto_publish: Invalid parameter, topic is NULL.\n");
        return MOSQ_ERR_INVAL;
    }

    if (payload == NULL) {
        logger("ERROR", "exim_mosquitto_publish: Invalid parameter, payload is NULL.\n");
        return MOSQ_ERR_INVAL;
    }

    int result = mosquitto_publish(mosq, mid, topic, payloadlen, payload, qos, retain);
    if (result == MOSQ_ERR_SUCCESS) {
        logger("INFO", "mosquitto_publish: Success\n");
    } else {
        logger("ERROR", "mosquitto_publish: Failed with error code %d, %s\n", result, strerror(errno));
    }

    return result;
}


/**
 * Breif:
 * Wrapper function for subscribing to an MQTT topic using the Mosquitto library.
 * This function subscribes to a specific topic with the specified quality of service (QoS0) level.
 * 
 * Parameters:
 * mosq - The Mosquitto client object.
 * mid  - Pointer to the message ID for the subscription. This can be NULL if not needed.
 * sub  - The topic to subscribe to.
 * qos  - The quality of service level for the subscription (0, 1, or 2).
 * 
 * Return: result of the `mosquitto_subscribe` function call (0 for success, non-zero for failure).
 */
int exim_mosquitto_subscribe(struct mosquitto *mosq, int *mid, const char *sub, int qos) {
    if (mosq == NULL || sub == NULL) {
        logger("ERROR", "exim_mosquitto_subscribe: Invalid parameter(s), mosq or sub is NULL.\n");
        return MOSQ_ERR_INVAL;
    }

    int result = mosquitto_subscribe(mosq, mid, sub, qos);
    if (result == MOSQ_ERR_SUCCESS) {
        logger("INFO", "mosquitto_subscribe: Success\n");
    } else {
        logger("ERROR", "mosquitto_subscribe: Failed with error code %d, %s\n", result, strerror(errno));
    }
    return result;
}

/**
* Breif: 
* This function wraps the `mosquitto_strerror` function from the Mosquitto library,
* which translates an error code into a human-readable error string. 
* 
* Parameters:
* mosq_errno - The error code returned by a Mosquitto function.
* 
* Return: A string describing the error associated with the provided error code.
*/
const char* exim_mosquitto_strerror(int mosq_errno) {
    if (mosq_errno < 0) {
        logger("ERROR", "exim_mosquitto_strerror: Invalid error code %d\n", mosq_errno);
        return strerror(errno);
    }

    const char *error = mosquitto_strerror(mosq_errno);
    logger("ERROR", "mosquitto_strerror: %s\n", error);
    return error;
}


/**
 * Breif:
 * Starts an event loop for the Mosquitto client that runs indefinitely.
 * ensures the client remains connected to the broker until an error occurs or the loop is terminated.
 * 
 * Parameters:
 * mosq        - A pointer to the initialized Mosquitto client instance.
 * timeout     - Maximum number of milliseconds to wait for network activity 
 *             before performing periodic maintenance tasks.
 * max_packets - Maximum number of messages to process per iteration.
 * 
 * Return: Returns `MOSQ_ERR_SUCCESS` (0) on success, or an error code on failure
 */
int exim_mosquitto_loop_forever(struct mosquitto *mosq, int timeout, int max_packets) {
    if (mosq == NULL) {
        logger("ERROR", "exim_mosquitto_loop_forever: mosq is NULL.\n");
        return MOSQ_ERR_INVAL;
    }

    int result = mosquitto_loop_forever(mosq, timeout, max_packets);
    if (result == MOSQ_ERR_SUCCESS) {
        logger("INFO", "mosquitto_loop_forever: Success\n");
    } else {
        logger("ERROR", "mosquitto_loop_forever: Failed with error code %d, %s\n", result, strerror(errno));
    }

    return result;
}