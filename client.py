import socket
import sys
import threading
import secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

default_ip_address = "127.0.0.1"
default_port = 12345

#default secret key for testing purposes
aes_secret_key =  b'\xa3\xec\xe0\x94\xec\xa9\xc4\xca\xc1\xb2\xbcI\xa9\xcf\xed\xa9'
    
print(secrets.token_bytes(16))

#if an ip address and port are not provided use default values for testing 
if len(sys.argv) == 3:
    ip_address = str(sys.argv[1])
    port = int(sys.argv[2])
else:
    print("Using default IP address and port for testing.")
    ip_address = default_ip_address
    port = default_port

try:
    client.connect((ip_address, port))
except Exception as e:
    print("Error connecting to the server:", e)
    sys.exit(1)
    
#decode messages recieved from the server 
def receive_messages():
    while True:
        message = client.recv(2048)
        if not message:
            print("Disconnected from the server.")
            sys.exit(0)
        else:
            if message.startswith(b"AES"):
                print(message)
                print("decoding...")
                iv = message[len(b"AES"):len(b"AES")+16]
                encrypted_message = message[len(b"AES")+16:]
                cipher = AES.new(aes_secret_key, AES.MODE_CBC, iv)
                decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size).decode()
                print(decrypted_message)
            else:
                print("\n" + message.decode())

# Start a separate thread to receive messages from the server
receive_thread = threading.Thread(target=receive_messages)
receive_thread.daemon = True
receive_thread.start()

while True:
    try:
        print("\nOptions:")
        print("1. Send message")
        print("2. Send AES encrypted message")
        
        choice = input("Select an option: ")
        
        if choice == "1":
            message = input()
            client.send(message.encode())
        elif choice == "2":
            message = input()
            block_size = 16
            padded_message = message.encode() + bytes([block_size - len(message) % block_size]) * (block_size - len(message) % block_size)
            initializationVector = get_random_bytes(16)
            cipher = AES.new(aes_secret_key, AES.MODE_CBC, initializationVector)
            ciphertext = cipher.encrypt(padded_message)
            transmission = b"AES" + initializationVector + ciphertext
            print(transmission)
            client.send(transmission)
    except KeyboardInterrupt:
        print("\nUser interrupted.")
        client.close()
        sys.exit(0)
    except Exception as e:
        print("Error sending message:", e)
        client.close()
        sys.exit(1)