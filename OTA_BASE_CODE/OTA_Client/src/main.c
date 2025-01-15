/*
 * Copyright (c) 2025 Eximietas Design India Pvt. Ltd.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eximietas Design India Pvt. Ltd. 
 * proprietary license.
 *
 * File: main.c
 * Description:
 *    The entry point of the application that initializes an MQTT client,
 *    establishes a connection to the MQTT broker, and processes messages
 *    continuously.
 * 
 * Key Functionalities:
 *   - Initializes the Mosquitto library for MQTT operations.
 *    - Creates an MQTT client instance.
 *    - Connects the client to a specified MQTT broker.
 *    - Enters a loop to process MQTT messages and maintain the connection.
 *    - Cleans up resources upon termination.
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

/**
 * Brief:
 * This program initializes an MQTT client using the Mosquitto library, 
 * connects it to an MQTT broker, and starts a loop to handle messages continuously.
 * 
 * Parameters: None
 * 
 * Return: 
 *  - 0 on successful execution.
 *  - 1 if there are errors during initialization or execution.
 */
int main() {
    struct mosquitto *mosq;

    // Initialize mosquitto library for mqtt operations
    exim_mosquitto_lib_init();

    // Create a new Mosquitto instance used for MQTT communication
    mosq=exim_mosquitto_new(NULL, true, NULL);

    
    //Connects the specified Mosquitto client (mosq) to the MQTT broker.
    connect_to_mqtt_broker(mosq);
   
    // Start the MQTT loop to continuously process incoming messages
    exim_mosquitto_loop_forever(mosq, 3000, 1);
  
    //Cleans up and frees resources associated with the Mosquitto client instance.
    exim_mosquitto_destroy(mosq);
    return 0;
}

