import socket
import select
import sys
import threading

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

default_ip_address = "127.0.0.1"
default_port = 12345

#initialize server with parameters if none are provided utilize default values 
if len(sys.argv) == 3:
    ip_address = str(sys.argv[1])
    port = int(sys.argv[2])
else:
    print("Using default IP address and port for testing.")
    ip_address = default_ip_address
    port = default_port

server.bind((ip_address, port))


print("Server active! Bound to: \nAddress:" + str(ip_address) + "\nPort: " + str(port) + "\nListening...")
server.listen(50)

client_list = []

def remove(connection):
    if connection in client_list:
        client_list.remove(connection)

def clientthread(connection, address):
    
    while True:
        try:
            # Use select.select() to check if there is data to read
            read_sockets, _, _ = select.select([connection], [], [], 5)  # 5-second timeout
            for sock in read_sockets:
                message = sock.recv(2048)
                if message:
                    print("<" + address[0] + "> " + message.decode())
                    messageOut = "<" + address[0] + "> " + message.decode()
                    broadcast(messageOut, sock)
                else:
                    remove(connection)
        except Exception as e:
            print("Error:", e)
            remove(connection)
            break 

#send messages recieved from clients to other connected clients 
def broadcast(message, sender_connection):
    for client_socket in client_list:
        if client_socket != sender_connection:
            try:
                client_socket.send(message.encode())
            except Exception as e:
                print("Error broadcasting message:", e)
                remove(client_socket)

while True:
    
    connection, address = server.accept()
    
    client_list.append(connection)
    
    print(address[0] + " connected")
    
    client_thread = threading.Thread(target=clientthread, args=(connection, address))
    client_thread.start()
    

    
             
                