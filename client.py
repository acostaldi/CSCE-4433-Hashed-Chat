import socket
import sys
import threading

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

default_ip_address = "127.0.0.1"
default_port = 12345

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

def receive_messages():
    while True:
        message = client.recv(2048).decode()
        if not message:
            print("Disconnected from the server.")
            sys.exit(0)
        else:
            print(message)

# Start a separate thread to receive messages from the server
receive_thread = threading.Thread(target=receive_messages)
receive_thread.daemon = True
receive_thread.start()

while True:
    try:
        message = input("<You> ")
        client.send(message.encode())
    except KeyboardInterrupt:
        print("\nUser interrupted.")
        client.close()
        sys.exit(0)
    except Exception as e:
        print("Error sending message:", e)
        client.close()
        sys.exit(1)