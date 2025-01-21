#include "../include/exim_mqtt.h"
#include "../include/file_transfer_utils.h"
#include <errno.h>

char client_ip[100];  // To store client IP received from the version message

/**
 * Brief:
 * Initializes the Mosquitto library for MQTT communication.
 * This function calls `mosquitto_lib_init` to initialize the Mosquitto library,
 * setting up internal resources and preparing the library for subsequent operations.
 * 
 * Parameters: None
 * 
 * Return: None
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
 * Brief:
 * Creates a new Mosquitto client instance for MQTT communication.
 * This function generates an MQTT client that can connect to a broker, subscribe to topics,
 * and publish messages. The client ID must be unique per broker. If `NULL`, the library generates a random ID.
 *
 * Parameters:
 * id - A string representing the client ID. Can be NULL for a random ID.
 * clean_session - A boolean indicating whether to start with a clean session.
 * userdata - A pointer to custom user-defined data that can be accessed in callbacks.
 * 
 * Return:
 * A pointer to the created `struct mosquitto` object if successful, or `NULL` if failed.
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


/**
 * Brief:
 * Connects an MQTT client to the broker at the specified host and port.
 * If the connection is successful, subscribes to relevant topics and performs other setup.
 * Handles connection failures by logging error messages based on the error code.
 *
 * Parameters:
 * mosq - A pointer to the Mosquitto client instance.
 * host - The hostname or IP address of the MQTT broker.
 * port - The port number on which the MQTT broker is listening.
 * keepalive - The maximum time interval between messages sent or received.
 * 
 * Return:
 * Integer indicating the result of the connection attempt.
 */
int exim_mosquitto_connect(struct mosquitto *mosq, const char *host, int port, int keepalive) {
    if (mosq == NULL || host == NULL) {
        logger("ERROR", "exim_mosquitto_connect: Invalid parameter(s), mosq or host is NULL.\n");
        return MOSQ_ERR_INVAL; // Return an error code for invalid parameters
    }

    int result = mosquitto_connect(mosq, host, port, keepalive);
    if (result == MOSQ_ERR_SUCCESS) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Successfully connected to broker at %s:%d with keepalive %d", host, port, keepalive);
        logger("INFO", msg);  // Log info level message
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
    }

    return result; // Return the connection result
}



/**
 * Brief:
 * Destroys the Mosquitto client instance and frees the associated resources.
 * This function ensures that all memory and resources allocated for the Mosquitto client are properly freed.
 * 
 * Parameters:
 * mosq - A pointer to the Mosquitto client instance to be destroyed.
 * 
 * Return: None
 */
void exim_mosquitto_destroy(struct mosquitto *mosq) {
    if (mosq == NULL) {
        logger("ERROR", "exim_mosquitto_destroy: mosq is NULL.\n");
        return;
    }

    mosquitto_destroy(mosq);
    logger("INFO", "mosquitto_destroy: Success\n");
}

/**
 * Brief:
 * Cleans up and releases resources used by the Mosquitto library.
 * This function ensures that all internal library resources, such as memory and networking handles,
 * are properly freed when the Mosquitto client is no longer needed.
 * 
 * Parameters: None
 * 
 * Return: None
 */
void exim_mosquitto_lib_cleanup() {
    int result = mosquitto_lib_cleanup();
    if (result == MOSQ_ERR_SUCCESS) {
        logger("INFO", "mosquitto_lib_cleanup: Success\n");
    } else {
        logger("ERROR", "mosquitto_lib_cleanup: Failed with error code %d\n", result);
    }
}

/**
 * Brief:
 * Handles actions upon successful or failed connection to the MQTT broker.
 * This callback function subscribes to specific topics upon successful connection.
 *
 * Parameters:
 * mosq      - Pointer to the MQTT client instance.
 * userdata  - User-defined data passed to the callback.
 * rc        - Return code indicating the connection status (0 for success, non-zero for failure).
 *
 * Return: None
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
 * Brief:
 * Callback function for handling incoming messages on subscribed topics.
 * It processes the message based on the topic it was published to, parsing the payload 
 * and taking appropriate actions (such as sending a file or logging an acknowledgment).
 * 
 * Parameters:
 * mosq - The Mosquitto client object.
 * userdata - User-defined data passed to the callback.
 * message - The message object containing the topic, payload, and additional details.
 * 
 * Return: None
 */
void exim_on_message(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message) {
    if (message->payloadlen > 0) {
        logger("INFO", "Received message on topic %s: %s\n", message->topic, (char *)message->payload);

        // Check if the message is from the TOPIC_DEVICE_VERSION topic
        if (strcmp(message->topic, TOPIC_DEVICE_VERSION) == 0) {
            int version;
            char client_ip[100];  // Assuming client_ip is of size 100
            // Extract the client IP address and version number from the payload string.
            if (sscanf((char *)message->payload, "%99[^:]:%d", client_ip, &version) == 2) {
                logger("INFO", "Extracted client IP: %s, version: %d\n", client_ip, version);
                
                if (is_device_selected(client_ip)) {
                    logger("INFO", "Device %s selected, preparing to send file.\n", client_ip);
                    // Call send_file_in_bytes without checking return value
                    send_file_in_bytes(mosq, file_path, client_ip);  // No return value check
                    logger("INFO", "File sending attempt made for device %s.\n", client_ip);
                } else {
                    logger("WARN", "Device %s is not selected. Skipping file send.\n", client_ip);
                }
            } else {
                logger("ERROR", "Failed to parse payload for TOPIC_DEVICE_VERSION. Payload: %s\n", (char *)message->payload);
            }
        }
        
        // Handle acknowledgment from the subscriber(device)
        else if (strncmp(message->topic, TOPIC_DEVICE_ACK, strlen(TOPIC_DEVICE_ACK)) == 0) {
            logger("INFO", "Acknowledgment received on topic %s: %s\n", message->topic, (char *)message->payload);

            // Additional processing for acknowledgment, if needed
            // For example, check if the payload contains a certain message (success/failure)
            if (strcmp((char *)message->payload, "success") == 0) {
                logger("INFO", "Acknowledgment indicates success for topic %s.\n", message->topic);
            } else {
                logger("WARN", "Acknowledgment indicates failure or unknown status for topic %s.\n", message->topic);
            }
        } else {
            logger("INFO", "Received message on an unknown topic: %s\n", message->topic);
        }
    } else {
        logger("WARN", "Received message with no payload on topic %s. Skipping.\n", message->topic);
    }
}


/**
 * Brief:
 * Sets a callback function to handle MQTT connection events.
 * 
 * Parameters:
 * mosq - A pointer to the initialized Mosquitto client instance.
 * on_connect - A pointer to the callback function to handle connection events.
 * 
 * Return: None
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
 * Brief:
 * Sets a callback function to handle incoming MQTT messages.
 * 
 * Parameters:
 * mosq - A pointer to the initialized Mosquitto client instance.
 * on_message - A pointer to the callback function to handle incoming messages.
 * 
 * Return: None
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
 * Brief:
 * Publishes a message to the specified MQTT topic.
 * 
 * Parameters:
 * mosq - Pointer to the Mosquitto client instance.
 * mid - Pointer to an integer to store the message ID, or NULL if not required.
 * topic - The MQTT topic to which the message is to be published.
 * payloadlen - The length of the payload in bytes.
 * payload - Pointer to the message payload.
 * qos - Quality of Service level for the message.
 * retain - Boolean flag indicating whether the message should be retained by the broker.
 * 
 * Return:
 * Integer indicating the result of the publish operation.
 */
int exim_mosquitto_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain) {
    // Check if mosq is NULL
    if (mosq == NULL) {
        logger("ERROR", "exim_mosquitto_publish: mosq is NULL.\n");
        return MOSQ_ERR_INVAL;
    }

    // Check if topic is NULL
    if (topic == NULL) {
        logger("ERROR", "exim_mosquitto_publish: topic is NULL.\n");
        return MOSQ_ERR_INVAL;
    }

    // Check if payload is NULL
    if (payload == NULL) {
        logger("ERROR", "exim_mosquitto_publish: payload is NULL.\n");
        return MOSQ_ERR_INVAL;
    }

    // Proceed with the publish if all parameters are valid
    int result = mosquitto_publish(mosq, mid, topic, payloadlen, payload, qos, retain);
    
    if (result == MOSQ_ERR_SUCCESS) {
        logger("INFO", "mosquitto_publish: Success. Topic: %s, Payload Length: %d, QoS: %d, Retain: %d\n", topic, payloadlen, qos, retain);
    } else {
        logger("ERROR", "mosquitto_publish: Failed with error code %d, %s. Topic: %s, Payload Length: %d, QoS: %d, Retain: %d\n", 
               result, strerror(errno), topic, payloadlen, qos, retain);
    }

    return result;
}


/**
 * Brief:
 * Subscribes to a specific MQTT topic with the given quality of service level.
 * 
 * Parameters:
 * mosq - The Mosquitto client instance.
 * mid - Pointer to the message ID for the subscription.
 * sub - The topic to subscribe to.
 * qos - The QoS level for the subscription (0, 1, or 2).
 * 
 * Return:
 * The result of the subscription attempt.
 */
int exim_mosquitto_subscribe(struct mosquitto *mosq, int *mid, const char *sub, int qos) {
    // Check if mosq is NULL
    if (mosq == NULL) {
        logger("ERROR", "exim_mosquitto_subscribe: mosq is NULL.\n");
        return MOSQ_ERR_INVAL;
    }

    // Check if sub is NULL
    if (sub == NULL) {
        logger("ERROR", "exim_mosquitto_subscribe: sub is NULL.\n");
        return MOSQ_ERR_INVAL;
    }

    // Proceed with the subscribe if all parameters are valid
    int result = mosquitto_subscribe(mosq, mid, sub, qos);
    
    if (result == MOSQ_ERR_SUCCESS) {
        logger("INFO", "mosquitto_subscribe: Success. Topic: %s, QoS: %d\n", sub, qos);
    } else {
        logger("ERROR", "mosquitto_subscribe: Failed with error code %d, %s. Topic: %s, QoS: %d\n", 
               result, strerror(errno), sub, qos);
    }

    return result;
}

/**
 * Brief:
 * Converts Mosquitto error codes into human-readable strings.
 * 
 * Parameters:
 * mosq_errno - The error code to translate.
 * 
 * Return:
 * A string describing the error associated with the provided error code.
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
 * Brief:
 * Runs the Mosquitto event loop indefinitely.
 * Ensures the client remains connected to the broker until an error occurs or the loop is terminated.
 * 
 * Parameters:
 * mosq - A pointer to the Mosquitto client instance.
 * timeout - The maximum time to wait for network activity., 10s
 * max_packets - The maximum number of messages to process per iteration. 1
 * 
 * Return:
 * Returns `MOSQ_ERR_SUCCESS` (0) on success, or an error code on failure.
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



