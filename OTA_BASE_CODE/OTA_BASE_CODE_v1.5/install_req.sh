#!/bin/bash

# Ensure the script runs as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please use 'su' to switch to root before running."
    exit 1
fi

# Install build-essential for compiling programs
echo "Installing build-essential..."
apt install -y build-essential || { echo "Failed to install build-essential"; exit 1; }

# Update package lists
echo "Updating package lists..."
apt update || { echo "Failed to update package lists"; exit 1; }

# Install Mosquitto broker and clients
echo "Installing Mosquitto and Mosquitto clients..."
apt install -y mosquitto mosquitto-clients || { echo "Failed to install Mosquitto"; exit 1; }

# Install Mosquitto development libraries
echo "Installing libmosquitto-dev..."
apt install -y libmosquitto-dev || { echo "Failed to install libmosquitto-dev"; exit 1; }

echo "All required packages have been installed successfully!"

# Start the device
DEVICE_PATH="/home/$USER/Downloads/Device"

if [ -d "$DEVICE_PATH" ]; then
    echo "Starting the device..."
    chmod 777 "$DEVICE_PATH" -R || { echo "Failed to set permissions for $DEVICE_PATH"; exit 1; }

    # Navigate to OTA_Client directory and build the project
    OTA_CLIENT_PATH="$DEVICE_PATH/OTA_Client"
    if [ -d "$OTA_CLIENT_PATH" ]; then
        cd "$OTA_CLIENT_PATH" || { echo "Failed to navigate to $OTA_CLIENT_PATH"; exit 1; }
        make clean
        make || { echo "Build failed in $OTA_CLIENT_PATH"; exit 1; }
    else
        echo "Directory $OTA_CLIENT_PATH not found. Skipping build."
    fi
else
    echo "Device path $DEVICE_PATH not found. Skipping device setup."
fi

