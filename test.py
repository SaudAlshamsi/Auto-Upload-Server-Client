import os
import socket
IPaddress=socket.gethostbyname(socket.gethostname())
if IPaddress=="127.0.0.1":
    print("No internet, your localhost is "+ IPaddress)
else:
    print("Connected, with the IP address: "+ IPaddress )