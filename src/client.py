import socket


s = socket.socket()         # Create a socket object
host = socket.gethostname() # Get local machine name
# host = PCIP
port = 12345                # Reserve a port for your service.

# print(host)

s.connect((host, port))
msg = ""
while msg != "stop":
    msg = s.recv(1024)
    if msg != "":
        print(msg)
s.close()                     # Close the socket when done
