# CSCE4433-HMAC-RSA-Chat

Note: This App requires Python and the pycryptodome library to be installed.

Python based chat app allowing for clients to communicate over a hosted server with options for HMAC and RSA Signed verification.

# Basic Operation:

To open a server(leave last two args blank to use default values)

/python server.py (ip_address) (port)

To open a client to connect to the server(leave last two args blank to use default values)

/python client.py (ip_address) (port)

# Available Build Scripts:

benchmark_hmac_rsa.bat
To benchmark the average time for HMAC generation and RSA signing and verification.

testcollision.bat
To test how long it takes to find a collision with the first 8 bits of HMAC.

test.bat
Open a new server defaulted to localhost and a defualt port and two clients defaulted to to the same origins to allow testing of chat features and encrypted chat features.
