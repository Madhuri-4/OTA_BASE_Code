#ifndef EXIM_MQTT_H
#define EXIM_MQTT_H

#include <stdlib.h>
#include <mosquitto.h>

// Function to initialize the mosquitto library
void exim_mosquitto_lib_init();

//function for setting the username and password for the Mosquitto client.
int exim_mosquitto_username_pw_set(struct mosquitto *mosq, const char *username, const char *password) ;

//function for setting the TLS options (certificate files) for the Mosquitto client.
int exim_mosquitto_tls_set(struct mosquitto *mosq, const char *cafile, const char*capath, const char*cerfile, const char*keyfile, const char*password);

// Function to create a new mosquitto client instance
struct mosquitto* exim_mosquitto_new(const char *id, bool clean_session, void *userdata);

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

// Function to run the mosquitto client in a blocking loop
int exim_mosquitto_loop_forever(struct mosquitto *mosq, int timeout, int max_packets);

#endif// EXIM_MQTT_H