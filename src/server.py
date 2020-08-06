import socket
import sys


# s = socket.socket()         # Create a socket object
# host = socket.gethostname() # Get local machine name
# port = 12345                # Reserve a port for your service.
# s.bind((host, port))        # Bind to the port
#
# print("Host = " + host)
#
# s.listen(5)                 # Now wait for client connection.
#
#
# a = None
# while a is None:
#    a = s.accept()     # Establish connection with client.
#
# c, addr = a
# print(c)
# print(addr)
#
# while True:
#    print('Got connection from', addr)
#    text = input("Write something: ")
#    c.send(bytes(text, 'utf-8'))
# c.close()                # Close the connection


def get_ports():
    """ Get the 3 ports given on the command line when the file is run. """
    ports = []
    if len(sys.argv) == 4:
        for i in range(1, 4):
            ports.append(int(sys.argv[i]))
    else:
        raise Exception("Server needs 3 ports!")
    return ports


if __name__ == '__main__':
    print(get_ports())
