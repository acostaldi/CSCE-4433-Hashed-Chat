# CSCE4433-Encrypted-Chat

Note: This App requires Python and the pycryptodome library to be installed.

Python based chat app allowing for clients to communicate over a hosted server with options for RSA and AES decryption and encryption.

Basic Operation:

To open a server(leave last two args blank to use default values)

/python server.py (ip_address) (port)

To open a client to connect to the server(leave last two args blank to use default values)

/python client.py (ip_address) (port)

Available Build Scripts:

benchmark.bat
To benchmark the average time for encryptin and decrypting with AES(128-bit, 192-bit, and 256-bit keys) and RSA( 1024-bit, 2048-bit, and 4096-bit keys) and return the average time.

test.bat
Open a new server defaulted to localhost and a defualt port and two clients defaulted to to the same origins to allow testing of chat features and encrypted chat features.
