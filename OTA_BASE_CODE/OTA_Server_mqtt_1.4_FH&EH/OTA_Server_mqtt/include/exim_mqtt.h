#ifndef EXIM_MQTT_H
#define EXIM_MQTT_H

//header files
#include <mosquitto.h> // Include for Mosquitto-related types

// Macros
#define TOPIC_DEVICE_VERSION "device/info"   //MQTT topic to read the device id and current version
#define TOPIC_DEVICE_ACK "File/Ack"             //MQTT topic to receive the acknowledgment from the device once file transfer is success
#define CHUNK_SIZE 1048576 // 1MB chunks          //maximum file size
#define BROKER_ADDRESS "dfd171ee7540472f9e5b2b1dfeb706b8.s1.eu.hivemq.cloud"    //Broker address used for MQTT connection
#define BROKER_PORT 8883                          //PORT number used to connect to the MQTT broker
#define USERNAME "hivemq.webclient.1733988288785"
#define PASSWORD "q1NkSy;#,5D<30AweJEf"

// Function to initialize the mosquitto library
void exim_mosquitto_lib_init();

// Function to create a new mosquitto client instance
struct mosquitto* exim_mosquitto_new(const char *id, bool clean_session, void *userdata);

//function for setting the username and password for the Mosquitto client.
int exim_mosquitto_username_pw_set(struct mosquitto *mosq, const char *username, const char *password);

//function for setting the TLS options (certificate files) for the Mosquitto client.
int exim_mosquitto_tls_set(struct mosquitto *mosq, const char *cafile, const char*capath, const char*cerfile, const char*keyfile, const char*password);

// Callback function to handle the connection event when the client successfully connects to the MQTT broker
void exim_on_connect(struct mosquitto *mosq, void *userdata, int rc);

// Function to connect the mosquitto client to the broker
int exim_mosquitto_connect(struct mosquitto *mosq, const char *host, int port, int keepalive);

// Callback function to handle incoming messages from the MQTT broker when the client subscribes to a topic
void exim_on_message(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message);

// Function to destroy the mosquitto client instance
void exim_mosquitto_destroy(struct mosquitto *mosq);

// Function to clean up the mosquitto library
void exim_mosquitto_lib_cleanup();

// Function to set the connection callback for the mosquitto client
void exim_mosquitto_connect_callback_set(struct mosquitto *mosq, void (*on_connect)(struct mosquitto *, void *, int));

// Function to set the message callback for the mosquitto client
void exim_mosquitto_message_callback_set(struct mosquitto *mosq, void (*on_message)(struct mosquitto *, void *, const struct mosquitto_message *));

// Function to publish a message using the mosquitto client
int exim_mosquitto_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain);

// Function to subscribe to a topic using the mosquitto client
int exim_mosquitto_subscribe(struct mosquitto *mosq, int *mid, const char *sub, int qos);

// Function to retrieve the error string for a mosquitto error code
const char* exim_mosquitto_strerror(int mosq_errno);

// Function to run the mosquitto client in a blocking loop
int exim_mosquitto_loop_forever(struct mosquitto *mosq, int timeout, int max_packets);

#endif // EXIM_MQTT_H

