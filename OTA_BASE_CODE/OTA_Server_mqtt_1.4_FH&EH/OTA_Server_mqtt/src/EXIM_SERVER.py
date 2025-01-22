import tkinter as tk                             # Importing the core Tkinter library for GUI creation
from tkinter import ttk, messagebox              # Importing specific Tkinter modules for enhanced widgets and message boxes
from tkinter.font import Font                    # Importing the Font module for customizing text fonts
from PIL import Image, ImageTk                   # Importing the PIL library for image handling in Tkinter
import hashlib                                   # Importing hashlib for secure hash and message digest generation
import re                                        # Importing the re module for regular expression operations
import json                                      # Importing json for handling JSON data
import os                                        # Importing os for interacting with the operating system
import time                                      # Importing time for time-related operations
import ctypes                                    # Importing ctypes for interfacing with C libraries and system-level functionality
import threading                                 # Importing threading for multi-threaded programming
import subprocess                                # Importing subprocess to run external commands and scripts
from tkinter import Tk, filedialog               # Importing Tk and filedialog for main window and file dialog interactions
from tkinter.filedialog import askopenfilename   # Importing askopenfilename for selecting files via a file dialog
from threading import Thread                     # Importing Thread for creating separate threads of execution
from concurrent.futures import ThreadPoolExecutor, as_completed  # Importing ThreadPoolExecutor and as_completed for thread pooling and task management


# Paths to the JSON files where user credentials will be stored
USER_CREDENTIALS_FILE = "user_credentials.json"

# Load the shared library for patch server functionality
libserver = ctypes.CDLL('./libpatchserver.so')

# Define argument and return types for the send_patch_to_clients function
send_patch_to_clients = libserver.send_patch_to_clients
send_patch_to_clients.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
send_patch_to_clients.restype = None

# Define argument and return types for the start_server function
start_server = libserver.start_server
start_server.argtypes = [ctypes.c_int]
start_server.restype = None

# Variable to hold protocol value(1. MQTT, 2. Socket)
key = None

# Dictionary to hold references to dynamically created checkboxes
checkbox_references = {} 

# Directory path for delta package files used in OTA updates
delta_package_dir = "/OTA/Delta_packages"

# Name of the firmware binary file
filename = "firmware_v1.1.bin"

# Global variable to store the MQTT clients
mqtt_clients = []

'''# This function starts the server on the specified port using the 'start_server' function.
    # If the server fails to start, an error message is displayed in a messagebox.'''
def run_server(port):
    try:
        start_server(port)
        root.after(0, lambda: print(f"Server started successfully on port {port}."))
    except Exception as e:
        root.after(0, lambda: messagebox.showerror("Error", f"Failed to start server: {e}"))

'''# This function runs the server based on the selected protocol (MQTT or Socket) using the 'key' variable.
    # It uses `subprocess.Popen` to execute the appropriate server command and handles any exceptions.'''
def run_server1():
    if key == 1:  # MQTT
        command = ["./publisher", patch_file_path]
    if key == 2:  #Socket
        command = "./server1" 
        try:
            subprocess.Popen(command, shell=True)
            print("server1 started successfully.")
        except Exception as e:
            print(f"Failed to start server1: {e}")

# Port number to be used for the server (can be customized as needed)
port_number = 8088  # Replace with your desired port number

# Start the server in a separate thread to handle connections concurrently
server_thread = threading.Thread(target=run_server, args=(port_number,))
server_thread.daemon = True # Ensures the thread exits when the main program ends
server_thread.start()

# Start the server1 in a separate thread to handle protocol-specific operations
server1_thread = threading.Thread(target=run_server1)
server1_thread.daemon = True # Ensures the thread exits when the main program ends
server1_thread.start()

''' # This function loads JSON data from the specified file and returns it as a dictionary.
    # If the file does not exist, is empty, or contains invalid JSON, an empty dictionary is returned.'''
def load_json(file_path):
    """Load JSON data from a file, return an empty dictionary if file does not exist or is empty."""
    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        with open(file_path, 'r') as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return {}
    return {}

'''# This function saves the provided data as JSON to the specified file path.
    # It overwrites the file content if the file already exists.'''
def save_json(data, file_path):
    """Save JSON data to a file."""
    with open(file_path, 'w') as file:
        json.dump(data, file)

# Load existing user credentials (username and hashed password)
user_credentials = load_json(USER_CREDENTIALS_FILE)

'''# This function retrieves the latest version file and its last updated time from the specified system's current_versions folder.
    # It returns the version and last updated time, or "N/A" if no files are found in the folder.'''
def get_version_info(system_name):
    folder_path = f"/OTA/{system_name}/current_versions"
    if os.path.exists(folder_path):
        files = os.listdir(folder_path)
        if files:
            # Get the latest file
            latest_file = max(files, key=lambda f: os.path.getmtime(os.path.join(folder_path, f)))
            # Extract version and last updated time
            version = latest_file.split(' ')[0]  # Assuming the version is the filename without extension
            last_updated = time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(os.path.getmtime(os.path.join(folder_path, latest_file))))
            return version, last_updated
    return "N/A", "N/A"

'''# This function creates a new window with a custom title, layout, and buttons for various actions.
    # It includes a table displaying version info for different systems (Cars, Mobiles, IOT) along with their last update time.'''
def open_new_page():
    new_window = tk.Toplevel(root)
    new_window.title("Eximietas Rsync configuration")
    new_window.geometry("1365x768")
    new_window.configure(bg='#f2f2f2')

    def on_new_window_close():
        new_window.destroy()
        root.destroy()

    new_window.protocol("WM_DELETE_WINDOW", on_new_window_close)

    # Create a frame to act as the box for the label
    label_frame = tk.Frame(new_window, bg='purple', bd=2, relief="solid")
    label_frame.pack(pady=20, padx=20, fill="x")

    # Add a label to the label_frame
    label = tk.Label(label_frame, text="Eximietas Rsync configuration", font=('Helvetica', 18, 'bold'), bg='purple', fg='white')
    label.pack(pady=20, padx=20)

    # Create a frame to act as the box for the buttons
    button_frame = tk.Frame(new_window, bg='purple', bd=2, relief="solid")
    button_frame.pack(pady=20, padx=20, fill="both", expand=True)

    # Add buttons to the button_frame using grid
    # Correcting the function name in the button command
    button_sw_version = tk.Button(button_frame, text="SW Version", font=('Helvetica', 16, 'bold'), bg='purple', fg='white', width=25, height=3)

    button_sw_version.grid(row=0, column=0, padx=(20, 10), pady=10, sticky="w")

    button_ota_server = tk.Button(button_frame, text="OTA Server", font=('Helvetica', 16, 'bold'), bg='purple', fg='white', width=25, height=3, command=open_ota_server_page)

    button_ota_server.grid(row=0, column=1, padx=10, pady=10, sticky="w")

    button_security = tk.Button(button_frame, text="Security", font=('Helvetica', 16, 'bold'), bg='purple', fg='white', width=25, height=3, command=show_security)
    button_security.grid(row=0, column=2, padx=10, pady=10, sticky="w")

    button_about = tk.Button(button_frame, text="About", font=('Helvetica', 16, 'bold'), bg='purple', fg='white', width=25, height=3, command=show_about)
    button_about.grid(row=0, column=3, padx=(10, 20), pady=10, sticky="w")

    # Configure row and column weights to make the content expand when the window is resized
    button_frame.grid_rowconfigure(0, weight=1)
    button_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

    # Create a frame to act as the box for the table
    table_outer_frame = tk.Frame(new_window, bg='purple', bd=2, relief="solid")
    table_outer_frame.pack(pady=20, padx=20, fill="both", expand=True)

    # Create a table with 4 rows and 3 columns
    table_frame = tk.Frame(table_outer_frame, bg='purple')
    table_frame.pack(pady=20, padx=20)

    # Manually add content to each cell with the first row having a purple background
    cell_content = [
            ["Systems", "Current SW Version", "Last Updated"],
            ["Cars", *get_version_info("Cars")],
            ["Mobiles", *get_version_info("Mobiles")],
            ["IOT", *get_version_info("IOT")]
            ]

    for row in range(4):
        for column in range(3):
            bg_color = 'gray' if row == 0 else 'white'  # Change background color of headers to black
            fg_color = 'white' if row == 0 else 'black'
            cell = tk.Label(table_frame, text=cell_content[row][column], bg=bg_color, fg=fg_color, borderwidth=1, relief="solid", width=30, height=3, font=('Helvetica', 14))
            cell.grid(row=row, column=column, padx=5, pady=5)
    # Configure row and column weights to make the content expand when the window is resized
    table_outer_frame.grid_rowconfigure(0, weight=1)
    table_outer_frame.grid_columnconfigure(0, weight=1)

# Displays an info message box with the "About" information of the software.
def show_about():
    messagebox.showinfo("About", "Remote Sync by Eximietas Design Ver1.0")

# Displays an info message box indicating that the security feature is coming soon.
def show_security():
    messagebox.showinfo("security", "Coming Soon         ")

#sw_page


#ota_page
'''# Centers the given window on the screen by calculating the appropriate x and y coordinates.
    # Sets the window's geometry to the specified width, height, and calculated position.'''
def center_window(window, width, height):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    window.geometry(f"{width}x{height}+{x}+{y}")

'''# Reads client configuration data from a CSV file, extracting client name, IP address, and status.
    # Adds the data to a list and inserts it into a treeview, handling the case where the file is not found.'''
def read_client_configurations(filename):
    try:
        with open(filename, "r") as file:
            for line in file:
                parts = line.strip().split(',')
                if len(parts) == 5:
                    client, ip_address, status = parts
                    clients.append((client, ip_address, status))
                    tree.insert("", "end", values=(client, ip_address, status))
    except FileNotFoundError:
        print(f"File {filename} not found.")

'''def add_radio_buttons(radio_frame):
    for i, client in enumerate(clients):
        var = tk.StringVar(value=client[2])
        enable_radio = ttk.Radiobutton(radio_frame, text="Enable", variable=var, value="Enable",
                                       command=lambda c=client[0], v=var: update_status(c, v.get()), style="Green.TRadiobutton")
        disable_radio = ttk.Radiobutton(radio_frame, text="Disable", variable=var, value="Disable",
                                        command=lambda c=client[0], v=var: update_status(c, v.get()), style="Red.TRadiobutton")
        enable_radio.grid(row=i, column=0, padx=5, pady=5, sticky='w')
        disable_radio.grid(row=i, column=1, padx=5, pady=5, sticky='w')'''

'''# Searches through the treeview to find the client and updates their status column with the new status.
    # Prints a debug message showing the updated client status after successfully modifying the entry.'''
def update_status(client, status):
    for item in tree.get_children():
        if tree.item(item, "values")[0] == client:
            tree.set(item, column="Status", value=status)
            print(f"Updated {client} status to {status}")  # For debugging
            break

# Displays the frame containing the input fields for adding a new client.
def show_add_client_inputs():
    new_client_frame.pack()

'''# Validates the user input for client name, IP address, and status, and displays an error message for invalid inputs.
    # If valid, adds the new client to the list, saves the configurations, updates the treeview, and hides the input frame.'''
def add_new_client():
    client_name = new_client_var.get()
    ip_address = new_ip_var.get()
    status = new_status_var.get()

    if not client_name or client_name.isspace():
        popup_message("Invalid Input", "Please provide a valid Client name.")
        return
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_address):
        popup_message("Invalid Input", "Please provide a valid IP address.")
        return
    if status not in ["Enable", "Disable"]:
        popup_message("Invalid Input", "Please select a valid Status.")
        return

    new_client = {
            "Client": client_name,
            "IP Address": ip_address,
            "Status": status
            }
    clients.append(new_client)
    save_client_configurations("client_configurations.txt")
    update_treeview()
    new_client_frame.pack_forget()

#function for opening the OTA Server page after login
def open_ota_server_page():
    global ip_var, ip_entry, ip_after_id, port_var, port_entry, port_after_id, clients, tree, radio_frame, new_client_var, new_ip_var, new_status_var, new_client_frame, key

    # Clears the entry field if it contains the default text and changes the text color to black.
    def clear_entry(event, entry, default_text):
        if entry.get() == default_text:
            entry.delete(0, tk.END)
            entry.config(foreground='black')

    # Resets the entry field to default text and changes the text color to grey if the field is empty.
    def reset_entry(event, var, default_text):
        if not var.get():
            var.set(default_text)
            event.widget.config(foreground='grey')

    # Schedules IP validation to be triggered after a 5-second delay, canceling any previous validation.
    def schedule_ip_validation(event):
        global ip_after_id
        if ip_after_id:
            root.after_cancel(ip_after_id)
        ip_after_id = root.after(5000, validate_ip)

    # Validates the entered IP address and changes the text color based on whether it is valid or not.
    def validate_ip():
        ip = ip_var.get()
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            ip_var.set("IP Address")
            ip_entry.config(foreground='grey')
        else:
            ip_entry.config(foreground='black')

    # Schedules port validation to be triggered after a 5-second delay, canceling any previous validation.
    def schedule_port_validation(event):
        global port_after_id
        if port_after_id:
            root.after_cancel(port_after_id)
        port_after_id = root.after(5000, validate_port)

    # Validates the entered port number and changes the text color based on whether it is valid or not.
    def validate_port():
        port = port_var.get()
        if not port.isdigit() or not (0 <= int(port) <= 65535):
            port_var.set("Port")
            port_entry.config(foreground='grey')
        else:
            port_entry.config(foreground='black')

    # Resets the input fields and displays the "Add Client" form.
    def show_add_client_inputs():
        new_client_var.set("")
        new_ip_var.set("")
        #new_status_var.set("Disable")
        new_client_frame.pack()

    # Validates if the given IP address is in correct format and each octet is between 0 and 255.
    def is_valid_ip(ip):
        return re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) and all(0 <= int(part) <= 255 for part in ip.split('.'))

    # Validates the IP address and adds a new client to the configuration if valid.
    def add_new_client():
        new_ip = new_ip_var.get()
        if not is_valid_ip(new_ip):
            popup_message("Invalid IP Address", "Please enter a valid IP address.")
            return

        new_client = {
                "Client": new_client_var.get(),
                "IP Address": new_ip,
                "Status": new_status_var.get(),
                "Old Version": old_version.get(),
                "Updated Version": new_version.get()
                }
        clients.append(new_client)
        save_client_configurations("client_configurations.txt")
        update_treeview()
        new_client_frame.pack_forget()

    # Displays a confirmation popup for client deletion and triggers the delete action if confirmed.
    def confirm_delete_clients():
        selected_items = tree.selection()
        if not selected_items:
            popup_message("No Selection", "Please select a client to delete.")
            return

        confirm_popup = tk.Toplevel(root)
        confirm_popup.title("Confirm Deletion")
        confirm_popup.geometry("500x150+500+300")
        confirm_popup.configure(bg="#E6E6FA")

        msg_label = ttk.Label(confirm_popup, text="Are you sure you want to delete the selected clients?", background="#E6E6FA")
        msg_label.pack(pady=20)

        button_frame = tk.Frame(confirm_popup, bg="#E6E6FA")
        button_frame.pack(pady=10)

        yes_button = ttk.Button(button_frame, text="Yes", command=lambda: delete_clients(selected_items, confirm_popup))
        yes_button.pack(side=tk.LEFT, padx=10)

        no_button = ttk.Button(button_frame, text="No", command=confirm_popup.destroy)
        no_button.pack(side=tk.LEFT, padx=10)

    def delete_clients(selected_items, popup_window):
        # Loop through each selected item in the treeview
        for item in selected_items:
            # Get the client data from the treeview item
            client_values = tree.item(item, "values")
            # Create a dictionary representing the client to be deleted
            client_to_delete = {
                    "Client": client_values[0],
                    "IP Address": client_values[1],
                    "Status": client_values[2],
                    "Old Version": client_values[3],
                    "Updated Version": client_values[4]
            }

            # Ensure that the client list is updated by removing the client_to_delete
            clients[:] = [client for client in clients if client != client_to_delete]

            # Delete the item from the treeview
            tree.delete(item)

        # Save the updated client list to the .txt file
        save_client_configurations("client_configurations.txt")

        # Close the popup window
        popup_window.destroy()

        # Update the treeview to reflect the changes
        update_treeview()

    # Open the specified file in write mode and save the client configurations to it
    def save_client_configurations(filename):
        with open(filename, 'w') as file:
            for client in clients:
                line = f"{client['Client']},{client['IP Address']},{client['Status']}, {client['Old Version']}, {client['Updated Version']}\n"
                file.write(line)

    # Load client configurations from the specified file and update the treeview
    def read_client_configurations(filename):
        global clients
        clients = load_client_configurations(filename)
        update_treeview()

    # Load client data from a file and return it as a list of dictionaries
    def load_client_configurations(filename):
        if not os.path.exists(filename):
            return []

        clients = []
        with open(filename, 'r') as file:
            for line in file:
                client_data = line.strip().split(',')
                if len(client_data) == 5:
                    client = {
                            "Client": client_data[0],
                            "IP Address": client_data[1],
                            "Status": client_data[2],
                            "Old Version": client_data[3],
                            "Updated Version": client_data[4]
                            }
                    clients.append(client)
        return clients

    # Clear all existing rows in Treeview and repopulate with updated data and checkboxes
    def update_treeview():
        global checkbox_references
        # Clear all existing rows in Treeview
        for item in tree.get_children():
            tree.delete(item)

        # Populate the Treeview with data and checkboxes
        for idx, client in enumerate(clients):
            client_name = client["Client"]

            # Ensure that the checkbox reference exists for this client
            if client_name not in checkbox_references:
                checkbox_references[client_name] = tk.BooleanVar(value=False)  # Default unchecked

            # Determine the checkbox symbol based on the current state of the BooleanVar
            checkbox_symbol = "☐" if not checkbox_references[client_name].get() else "✓"

            # Insert row into Treeview with the updated checkbox symbol
            tree.insert(
                "", "end",
                iid=idx,
                values=(checkbox_symbol, client["Client"], client["IP Address"], client["Status"],
                    client["Old Version"], client["Updated Version"])
            )

    def add_radio_buttons():
        for child in radio_frame.winfo_children():
            child.destroy()

        for index, client in enumerate(clients):
            status_var = tk.StringVar(value=client['Status'])
            enable_radio = ttk.Radiobutton(radio_frame, text="Enable", variable=status_var, value="Enable", command=lambda idx=index: update_client_status(idx, "Enable"), style="Green.TRadiobutton" if client['Status'] == "Enable" else "")
            disable_radio = ttk.Radiobutton(radio_frame, text="Disable", variable=status_var, value="Disable", command=lambda idx=index: update_client_status(idx, "Disable"), style="Red.TRadiobutton" if client['Status'] == "Disable" else "")

            if client['Status'] == "Enable":
                enable_radio.configure(style="Green.TRadiobutton")
            elif client['Status'] == "Disable":
                disable_radio.configure(style="Red.TRadiobutton")

            enable_radio.grid(row=index, column=0, padx=5, pady=2, sticky='w')
            disable_radio.grid(row=index, column=1, padx=5, pady=2, sticky='w')

    def update_client_status(index, status):
        clients[index]['Status'] = status
        save_client_configurations("client_configurations.txt")
        update_treeview()
    
    # Open the folder in the file explorer for Linux/macOS or display an error for unsupported OS
    """def open_local_folder(delta_package_dir):
        try:
            # Open the folder in the file explorer
            if os.name == 'posix':  # For Linux/macOS
                confirm_selection(delta_package_dir)
            else:
                print("Unsupported OS")      
        except Exception as e:
            print(f"Error opening folder: {e}")

    def confirm_selection(delta_package_dir):
        # Initialize Tkinter root window (required for using askopenfilename)
        root = tk.Tk()
        root.withdraw()  # Hide the root window

        # Open file dialog to select a patch file
        selected_patch = askopenfilename(initialdir=delta_package_dir, title="Select a Patch File")
        
        #if selected_patch:
            # If a patch file is selected, show an info message with the file path
            #tk.messagebox.showinfo("Patch Selected", f"Server updated the patch file: {selected_patch}\nFull Path: {selected_patch}")
        #else:
            # If no patch file is selected, show a warning
            #tk.messagebox.showwarning("Selection Error", "No patch file selected.")
        #send_firmware_to_selected_clients(tree, filename)
        root.destroy()  # Close the Tkinter root window"""
            
    def toggle_checkbox(event):
        # Get the selected row and its current checkbox state
        selected_item = tree.focus()  # Get the selected row
        current_status = tree.item(selected_item, 'values')[0]  # Get current checkbox state

        # Toggle the checkbox between '☐' and '☑'
        new_status = '☐' if current_status == '☑' else '☑'

        # Update the row with the new status
        row_values = list(tree.item(selected_item, 'values'))
        row_values[0] = new_status  # Update the first column with the new checkbox state
        tree.item(selected_item, values=tuple(row_values)) 
    
    #function to read the selected clients when checkbox is checked
    def get_selected_clients(tree):
        selected_devices = []
        # Loop through each row and check if the client is selected (checkbox is '☑')
        for client in tree.get_children():
            row_values = tree.item(client, 'values')
        
            # Check if the Status (first column) is checked (i.e., '☑')
            if row_values[0] == '☑':  # Status is at index 0
                selected_devices.append(row_values[1])  # Get the IP address (column 2)

        print(f"Selected devices: {selected_devices}")  # Debugging print
        if not selected_devices:
            messagebox.showerror("Client Selection Error", "No device selected, Please Select Atleast one device to send")
            return
        return selected_devices
    
    # Function to run publisher in a separate thread
    def start_publisher_thread(selected_devices):
        """Function to start the publisher in a separate thread to avoid blocking the GUI."""
        if not selected_devices:
            messagebox.showwarning("No Clients Selected", "Please select at least one client.")
            return  # No clients to process
        # Get the current value of 'action' from the StringVar
        '''action = action_var.get()
        if not action:
            messagebox.showwarning("No Action Selected", "Please select an action.")
            return'''

        publisher_thread = threading.Thread(target=run_publisher, args=(selected_devices, ), daemon=True)
        publisher_thread.start()
    
    def run_publisher(selected_devices):        
        try:
            # Convert the selected clients list to a comma-separated string
            selected_devices_id = ",".join(selected_devices)
            #print(f"Formatted selected_clients_str: {selected_clients_str}")
        
            # Set the PYTHONUNBUFFERED environment variable to ensure unbuffered output
            env = os.environ.copy()
            env['PYTHONUNBUFFERED'] = '1'
            env['DEVICE_LIST'] = "firmware/update"  # Ensure the topic is set dynamically
            env['SELECTED_DEVICES'] = selected_devices_id  # Pass selected clients as environment variable

            # Print environment variables for debugging
            #print(f"MQTT_TOPIC set in environment: {env.get('MQTT_TOPIC')}")
            #print(f"SELECTED_CLIENTS set in environment: {env.get('SELECTED_CLIENTS')}")

            # Start publisher script
            process = subprocess.Popen(
                ["stdbuf", "-oL", "./publisher"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffering for real-time output
                  # Pass environment variables
            )

            # Helper function to read and print output from a pipe
            def read_output(pipe):
                while True:
                    line = pipe.readline()
                    if line == '' and process.poll() is not None:
                        break
                    if line:
                        print(line.strip(), flush=True)  # Print and flush the output

            #Start separate threads to capture stdout and stderr
            threading.Thread(target=read_output, args=(process.stdout,), daemon=True).start()
            threading.Thread(target=read_output, args=(process.stderr,), daemon=True).start()

            # Wait for the process to finish
            process.wait()

            if process.returncode != 0:
                messagebox.showerror("MQTT Publisher Error", "C script encountered an error.")
            else:
                print(f"C script executed successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Error executing publisher script: {e}")

    #function used for working once upload button is clicked
    def update_server():
        delta_package_dir = "/OTA/Delta_packages"
        #open_local_folder(delta_package_dir)  # Pass the folder path to open_local_folder
        update_server_1()  # Assuming this function exists and does the necessary server update.

    def update_server_1():
        global key
        ip_address = ip_var.get()
        port = port_var.get()

        # Validate IP address
        if key == 2:  # Socket
            if not is_valid_ip(ip_address):
                popup_message("Invalid IP Address", "Please enter a valid IP address.")
                return

            # Validate port
            if not port.isdigit() or not (0 <= int(port) <= 65535):
                popup_message("Invalid Port", "Please enter a valid port number (0-65535).")
                return

        # Directory containing the patch files
        delta_package_dir = "/OTA/Delta_packages/"
        clients_filename = "client_configurations.txt"

        #try:
        # Find the patch file in the delta_packages directory
        patch_files = [f for f in os.listdir(delta_package_dir) if f.endswith('.bin')]
        if not patch_files:
           messagebox.showerror("Error", "No bin files found in the delta_packages directory.")
           return
            
        patch_file_name = "firmware_v1.1.bin"
        base_folder = "/OTA/Delta_packages/"
        patch_file_path = os.path.join(base_folder, patch_file_name)

        if not os.path.isfile(patch_file_path):
           messagebox.showerror("Bin File Error", f"The bin file {patch_file_path} does not exist.")
           return
               
        if key is None or key == 0:  # Check if key is not provided or invalid
           messagebox.showerror("Key Error", "Invalid key value.")
           return
                
        elif key == 1:  # MQTT
            selected_devices = get_selected_clients(tree)
            mqtt_clients = selected_devices
            #start_publisher_thread(selected_clients)

        elif key == 2:  # Socket
           client_command = ["./server1"]

        else:
           messagebox.showerror("Key Error", "Invalid key value.")
           return
                
        clients = load_client_configurations(clients_filename)
            
        # Assuming we take the first patch file found
        patch_file = patch_files[0]
        source_path = os.path.join(delta_package_dir, patch_file)
        if selected_devices:
            start_publisher_thread(selected_devices)
        #lib.cleanup_resources()
        # Call the send_patch_to_clients functions if you have for sending firmware update

        #messagebox.showinfo("Success", f"Server updated the patch file: {source_path}")
        
        #except Exception as e:
            #messagebox.showerror("Error", f"Error updating the server: {e}")
            
    def on_option_selected(option):
    # Handle the option selected here
        global key
        if option == 'MQTT':
            key = 1  # Example key value for MQTT
            ip_entry.config(state='disabled')  # Disable the IP & port entry
            port_entry.config(state='disabled')
        #messagebox.showinfo("Selection", "MQTT selected. Key: {}".format(key))
        elif option == 'Socket':
            ip_entry.config(state='normal')  # Enable the IP & port entry
            port_entry.config(state='normal')
            key = 2  # Example key value for Socket

    def show_menu(event):
    # Create a popup menu
        menu = tk.Menu(root, tearoff=0)
        menu.add_command(label="MQTT", command=lambda: on_option_selected('MQTT'))
        menu.add_command(label="Socket", command=lambda: on_option_selected('Socket'))
        menu.post(event.x_root, event.y_root)
        
    def popup_message(title, message):
        # Create a popup window with a message and an OK button to close it
        message_popup = tk.Toplevel(root)
        message_popup.title(title)
        message_popup.geometry("400x150+500+300")
        message_popup.configure(bg="#E6E6FA")

        msg_label = ttk.Label(message_popup, text=message, background="#E6E6FA", font=("Arial", 12))
        msg_label.pack(pady=20)

        ok_button = ttk.Button(message_popup, text="OK", command=message_popup.destroy)
        ok_button.pack(pady=10)

    # Initialize variables for IP address, port, and clients
    ip_after_id = None
    port_after_id = None
    clients = []
 
    # Create a new window for OTA Server Configuration
    ota_window = tk.Toplevel(root)
    ota_window.title("OTA Server Configuration")
    ota_window.geometry("1000x700")
    ota_window.configure(bg="#E6E6FA")

    # Configure styles for various widgets
    style = ttk.Style()
    style.configure("TLabel", foreground="black", font=("Arial", 14))
    style.configure("Green.TEntry", foreground="green")
    style.configure("Red.TEntry", foreground="red")
    style.configure("Green.TRadiobutton", foreground="green")
    style.configure("Red.TRadiobutton", foreground="red")

    # Create a frame for the title
    ota_title_frame = tk.Frame(ota_window, bg="#800080")
    ota_title_frame.pack(pady=10, fill='x')

    # Create and pack the title label
    title_label = ttk.Label(ota_title_frame, text="OTA Server Configuration", style="TLabel", font=("Arial", 18, "bold"), background="#800080", foreground="white")
    title_label.pack(pady=10)

    # Create a frame for the configuration inputs
    ota_config_frame = tk.Frame(ota_window, bg="#E6E6FA")
    ota_config_frame.pack(pady=5, fill='x')
    
    # Set dimensions and appearance for buttons
    button_width = 20
    button_height = 2
    button_padx = 10
    button_pady = 5
    button_bg = "#9A4EAE"
    button_fg = "white"
    button_relief = "raised"
    
    # Determine the maximum button width based on label text length
    max_button_width = max(len("OTA Server Configuration"), len("IP Address"), len("Port")) + 2
    
    # Configure custom button style
    style = ttk.Style()
    style.configure("Custom.TButton", background=button_bg)

    # Violet box for "OTA Server Address" label
    ota_server_frame = tk.Frame(ota_config_frame, bg="#800080")
    ota_server_frame.grid(row=0, column=2, padx=15, pady=5, sticky="w")

    # Create a button for the OTA server address
    ota_server_button = ttk.Button(ota_server_frame, text="OTA Server Address", width=max_button_width, style="Custom.TButton")
    ota_server_button.grid(row=0, column=0, padx=button_padx, pady=button_pady)
    
    # Bind a function to the button click event
    ota_server_button.bind("<Button-1>", show_menu)

    # Create input fields for IP Address and Port
    ip_var = tk.StringVar()
    ip_var.set("IP Address")
    ip_entry = ttk.Entry(ota_config_frame, textvariable=ip_var, font=("Arial", 14), width=25)
    ip_entry.grid(row=0, column=4, padx=(120, 10), pady=5, sticky="ew")  # Adjusted padx for more right alignment

    port_var = tk.StringVar()
    port_var.set("Port")
    port_entry = ttk.Entry(ota_config_frame, textvariable=port_var, font=("Arial", 14), width=20)
    port_entry.grid(row=0, column=8, padx=(120, 150), pady=5, sticky="ew")  # Adjusted padx for more right alignment

    # Bind focus events to the IP and Port entry fields
    ip_entry.bind("<FocusIn>", lambda event: clear_entry(event, ip_entry, "IP Address"))
    ip_entry.bind("<FocusOut>", lambda event: reset_entry(event, ip_var, "IP Address"))
    ip_entry.bind("<KeyRelease>", schedule_ip_validation)

    port_entry.bind("<FocusIn>", lambda event: clear_entry(event, port_entry, "Port"))
    port_entry.bind("<FocusOut>", lambda event: reset_entry(event, port_var, "Port"))
    port_entry.bind("<KeyRelease>", schedule_port_validation)

    # Create a frame for the client title
    client_title_frame = tk.Frame(ota_window, bg="#800080")
    client_title_frame.pack(pady=10, fill='x')

    # Create and pack the client label
    client_label = ttk.Label(client_title_frame, text="Client Configuration", style="TLabel", font=("Arial", 16, "bold"), background="#800080", foreground="white")
    client_label.pack(pady=10)

    # Create a frame for client configuration
    client_config_frame = tk.Frame(ota_window, bg="#E6E6FA")
    client_config_frame.pack(pady=5, fill='x')

    # Create a table frame for displaying client details
    table_frame = tk.Frame(client_config_frame, bg="#F0F8FF")
    table_frame.pack(pady=10, fill='both', expand=True)

    # Create a Treeview widget to display client configurations in a table format
    tree = ttk.Treeview(table_frame, columns=("Checkbox", "Client", "IP Address", "Status", "Old Version", "Updated Version", "Acknowledgement"), show="headings", height=8)
    tree.heading("Checkbox", text="Select")
    tree.heading("Client", text="Client")
    tree.heading("IP Address", text="IP Address")
    tree.heading("Status", text="Status")
    tree.heading("Old Version", text="Old Version")
    tree.heading("Updated Version", text="Updated Version")
    tree.heading("Acknowledgement", text="Acknowledgement")
    
    # Adjust the width for each column
    # When setting up the treeview:
    #tree["columns"] = ("Checkbox", "Client", "IP Address", "Status", "Old Version", "Updated Version", "Acknowledgement")
    tree.column("#0", width=0, stretch=tk.NO)  # Hide the first default column
    tree.column("Checkbox", width=10, anchor="center")  # Make the checkbox column wider if needed
    tree.column("Client", width=20, anchor="center") 
    tree.column("IP Address", width=50, anchor="center")  # Adjust width
    tree.column("Status", width=30, anchor="center")  # Adjust width
    tree.column("Old Version", width=60, anchor="center")  # Adjust width
    tree.column("Updated Version", width=80, anchor="center")  # Adjust width
    tree.column("Acknowledgement", width=80, anchor="center")  # Adjust width
    
    # Bind toggle_checkbox to left-click event on the Treeview
    tree.bind("<ButtonRelease-1>", toggle_checkbox)

    # Set heading alignment and column anchoring
    for col in ("Client", "IP Address", "Status", "Old Version", "Updated Version"):
        tree.heading(col, text=col, anchor="center")
        tree.column(col, anchor="center")

    # Pack the Treeview widget into the table frame
    tree.pack(side=tk.LEFT, padx=10, fill='both', expand=True)

    # Create a vertical scrollbar for the Treeview widget
    scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
    scrollbar.pack(side=tk.LEFT, fill=tk.Y)
    tree.configure(yscrollcommand=scrollbar.set)

    # Create a frame for radio buttons related to client configuration
    radio_frame = tk.Frame(table_frame, bg="#E6E6FA")
    radio_frame.pack(side=tk.LEFT, padx=10)

    # Read and configure client data from a file
    read_client_configurations("client_configurations.txt")
    #add_radio_buttons()

    # Create a frame for adding new clients
    new_client_frame = tk.Frame(client_config_frame, bg="#E6E6FA")
    new_client_frame.pack(pady=10)
    new_client_frame.pack_forget()

    # Create and configure input fields for adding new client details (Client, IP, Status, Old Version, Updated Version)
    ttk.Label(new_client_frame, text="Client:", background="#E6E6FA", font=("Arial", 14)).grid(row=0, column=0, padx=5, pady=5, sticky="e")
    new_client_var = tk.StringVar()
    new_client_entry = ttk.Entry(new_client_frame, textvariable=new_client_var, width=20, font=("Arial", 14))
    new_client_entry.grid(row=0, column=1, padx=5, pady=5)

    ttk.Label(new_client_frame, text="IP Address:", background="#E6E6FA", font=("Arial", 14)).grid(row=1, column=0, padx=5, pady=5, sticky="e")
    new_ip_var = tk.StringVar()
    new_ip_entry = ttk.Entry(new_client_frame, textvariable=new_ip_var, width=20, font=("Arial", 14))
    new_ip_entry.grid(row=1, column=1, padx=5, pady=5)

    ttk.Label(new_client_frame, text="Status:", background="#E6E6FA", font=("Arial", 14)).grid(row=2, column=0, padx=5, pady=5, sticky="e")
    new_status_var = tk.StringVar(value="Disable")
    new_status_enable_radio = ttk.Radiobutton(new_client_frame, text="Enable", variable=new_status_var, value="Enable")
    new_status_disable_radio = ttk.Radiobutton(new_client_frame, text="Disable", variable=new_status_var, value="Disable")
    new_status_enable_radio.grid(row=2, column=1, padx=5, pady=5, sticky="w")
    new_status_disable_radio.grid(row=2, column=2, padx=5, pady=5, sticky="w")
    
    # Create input fields for Old Version and Updated Version
    ttk.Label(new_client_frame, text="Old Version:", background="#E6E6FA", font=("Arial", 14)).grid(row=3, column=0, padx=5, pady=5, sticky="e")
    old_version = tk.StringVar()
    old_version_entry = ttk.Entry(new_client_frame, textvariable=old_version, width=20, font=("Arial", 14))
    old_version_entry.grid(row=3, column=1, padx=5, pady=5)
    
    ttk.Label(new_client_frame, text="Updated Version:", background="#E6E6FA", font=("Arial", 14)).grid(row=4, column=0, padx=5, pady=5, sticky="e")
    new_version = tk.StringVar()
    new_version_entry = ttk.Entry(new_client_frame, textvariable=new_version, width=20, font=("Arial", 14))
    new_version_entry.grid(row=4, column=1, padx=5, pady=5)

    #button for submit the add client details
    submit_button = ttk.Button(new_client_frame, text="Submit", command=add_new_client)
    submit_button.grid(row=5, column=0, columnspan=3, pady=10)

    button_frame = tk.Frame(ota_window, bg="#E6E6FA")
    button_frame.pack(pady=10, fill='x')

    #button for adding new client
    add_client_frame = tk.Frame(client_config_frame, bg="#E6E6FA")
    add_client_frame.pack(pady=10)
    add_client_button = ttk.Button(add_client_frame, text="Add Client", command=show_add_client_inputs)
    add_client_button.pack(side=tk.LEFT, padx=5)

    #button for deleting the client
    delete_client_button = ttk.Button(add_client_frame, text="Delete Client", command=confirm_delete_clients)
    delete_client_button.pack(side=tk.LEFT, padx=5)

    #button for sending the firmware update to device
    update_button = ttk.Button(add_client_frame, text="Upload", command=update_server)
    update_button.pack(side=tk.LEFT, padx=5)

    back_button = tk.Button(ota_window, text="Back", bg='#800080', fg='white', command=ota_window.destroy)
    back_button.place(relx=1.0, rely=1.0, anchor='se')

def open_signup_page():
    # Create a new window for the signup page
    new_window = tk.Toplevel(root)
    new_window.title("Signup")
    new_window.geometry("1365x768")
    new_window.configure(bg='#f2f2f2')

    def resize_image(event):
        # Resize the background image to fit the new window dimensions
        new_width = event.width
        new_height = event.height
        image = bg_image.resize((new_width, new_height), Image.LANCZOS)
        background_image = ImageTk.PhotoImage(image)
        canvas.create_image(0, 0, image=background_image, anchor="nw")
        canvas.image = background_image  # Keep a reference to avoid garbage collection

        # Update font size and widget sizes based on the new dimensions
        scale = new_width / 1365
        font_size = int(14 * scale)
        custom_font.config(size=font_size)
        button_width = int(15 * scale)
        button_height = int(2 * scale)

        button_register.config(width=button_width, height=button_height, font=custom_font)

    # Create a canvas widget to display the background image
    canvas = tk.Canvas(new_window) 
    canvas.pack(fill="both", expand=True)
    canvas.bind("<Configure>", resize_image)
    canvas.create_image(0, 0, image=background_image, anchor="nw")

    custom_font = Font(family="Helvetica", size=14)

    # Create label for username field and username input entry
    label_username_signup = tk.Label(new_window, text="New Username", bg='white', font=custom_font)
    entry_username_signup = tk.Entry(new_window, width=30, font=custom_font)

    # Create label for password field and password input entry
    label_password_signup = tk.Label(new_window, text="New Password", bg='white', font=custom_font)
    entry_password_signup = tk.Entry(new_window, show='*', width=30, font=custom_font)

    # Create label for confirm password field and confirm password input entry
    label_confirm_password_signup = tk.Label(new_window, text="Confirm Password", bg='white', font=custom_font)
    entry_confirm_password_signup = tk.Entry(new_window, show='*', width=30, font=custom_font)

    # Create label for password criteria
    label_password_criteria = tk.Label(new_window, text="Password must contain at least one special character, one number,\n and one uppercase letter.", bg='white', font=custom_font)

    # Create register button with callback
    button_register = tk.Button(new_window, text="Register", command=lambda: register(new_window, entry_username_signup.get(), entry_password_signup.get(), entry_confirm_password_signup.get()), bg='#800080', fg='#fff', width=15, height=2, font=custom_font)

    # X & Y offset for placing widgets
    x_offset = 0.58
    y_offset = 0.35

    # Position of all input entry labels
    label_username_signup.place(relx=x_offset, rely=y_offset, anchor="nw")
    entry_username_signup.place(relx=x_offset + 0.15, rely=y_offset, anchor="nw")
    label_password_signup.place(relx=x_offset, rely=y_offset + 0.05, anchor="nw")
    entry_password_signup.place(relx=x_offset + 0.15, rely=y_offset + 0.05, anchor="nw")
    label_confirm_password_signup.place(relx=x_offset, rely=y_offset + 0.1, anchor="nw")
    entry_confirm_password_signup.place(relx=x_offset + 0.15, rely=y_offset + 0.1, anchor="nw")
    label_password_criteria.place(relx=x_offset, rely=y_offset + 0.15, anchor="nw")
    button_register.place(relx=x_offset + 0.10, rely=y_offset + 0.25, anchor="nw")

#function for login once login button clicked open_new_page() will open
def login():
    # username = entry_username.get()
    # password = hashlib.sha256(entry_password.get().encode()).hexdigest()

    # if username in user_credentials and user_credentials[username] == password:
        # messagebox.showinfo("Login", "Login Successful")
        # root.withdraw()  # Hide the main login window

        # Open the new page only if root existed (root.withdraw() was successful)
        # if tk._default_root:  # Check if the default root still exists
     open_new_page()
    #else:
        # if messagebox.askyesno("Login Failed", "User not found. Do you want to register?"):
            # open_signup_page()
        # entry_username.delete(0, 'end')  # Clear the username entry
        # entry_password.delete(0, 'end')  # Clear the password entry

#function for registering the new user credentials
def register(window, username, password, confirm_password):
    if len(user_credentials) >= 5:
        messagebox.showerror("Register", "User limit reached. Cannot register more users.", parent=window)
        return
    if not re.match(r'^(?=.*[A-Z])(?=.*\d)(?=.*\W)', password):
        messagebox.showerror("Register", "Password must contain at least one special character, one number, and one uppercase letter.", parent=window)
    elif password != confirm_password:
        messagebox.showerror("Register", "Passwords do not match.", parent=window)
    elif username in user_credentials:
        messagebox.showerror("Register", "Username already exists.", parent=window)
    else:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        user_credentials[username] = hashed_password
        save_json(user_credentials, USER_CREDENTIALS_FILE)
        messagebox.showinfo("Register", "Registration Successful", parent=window)
        window.destroy()

def resize_image(event):
    new_width = event.width
    new_height = event.height
    image = bg_image.resize((new_width, new_height), Image.LANCZOS)
    background_image = ImageTk.PhotoImage(image)
    canvas.create_image(0, 0, image=background_image, anchor="nw")
    canvas.image = background_image  # Keep a reference to avoid garbage collection

    # Update font size and widget sizes based on the new dimensions
    scale = new_width / 1365
    font_size = int(14 * scale)
    custom_font.config(size=font_size)
    button_width = int(15 * scale)
    button_height = int(2 * scale)

    button_login.config(width=button_width, height=button_height, font=custom_font)
    button_signup.config(width=button_width, height=button_height, font=custom_font)

# Initializing the main Tkinter window with title and geometry
root = tk.Tk()
root.title("Login Page")
root.geometry("1365x768")

#background image for window
bg_image = Image.open("logo.jpg")

# Creating a canvas widget for drawing on the window
canvas = tk.Canvas(root)
canvas.pack(fill="both", expand=True)
canvas.bind("<Configure>", resize_image)
background_image = ImageTk.PhotoImage(bg_image)
canvas.create_image(0, 0, image=background_image, anchor="nw")

custom_font = Font(family="Helvetica", size=14)

label_username = tk.Label(root, text="Username", bg='white', font=custom_font)
entry_username = tk.Entry(root, width=30, font=custom_font)

label_password = tk.Label(root, text="Password", bg='white', font=custom_font)
entry_password = tk.Entry(root, show='*', width=30, font=custom_font)

button_login = tk.Button(root, text="Login", command=login, bg='#800080', fg='#fff', width=15, height=2, font=custom_font)

button_signup = tk.Button(root, text="Signup", command=open_signup_page, bg='#800080', fg='#fff', width=15, height=2, font=custom_font)

emoji_label = tk.Label(root, bg='#f2f2f2')

x_offset = 0.58
y_offset = 0.35

label_username.place(relx=x_offset, rely=y_offset, anchor="nw")
entry_username.place(relx=x_offset + 0.1, rely=y_offset, anchor="nw")
label_password.place(relx=x_offset, rely=y_offset + 0.05, anchor="nw")
entry_password.place(relx=x_offset + 0.1, rely=y_offset + 0.05, anchor="nw")
button_login.place(relx=x_offset + 0.025, rely=y_offset + 0.1, anchor="nw")
button_signup.place(relx=x_offset + 0.2, rely=y_offset + 0.1, anchor="nw")

# Start the Tkinter event loop to display the window
root.mainloop()

