import socket
import sys

MIN_PORT = 1024     # Inclusive
MAX_PORT = 64000    # Inclusive

NUM_PORTS = 3

MAGIC_NUMBER = 0x497E


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
    if len(sys.argv) == NUM_PORTS + 1:
        for i in range(1, NUM_PORTS + 1):
            port = int(sys.argv[i])
            if MIN_PORT <= port <= MAX_PORT:
                ports.append(port)
            else:
                raise Exception("Ports must be between {} and {} (inclusive)".format(MIN_PORT, MAX_PORT))
    else:
        raise Exception("Server needs 3 ports!")
    return ports


def get_socket(port):
    """ Get a new socket bound to this machine and port. """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)             # Create a socket object
    host = socket.gethostbyname(socket.gethostname())     # Get local machine name
    s.bind((host, port))            # Bind to the port
    return s


def get_sockets(ports):
    """ Get a socket for each port. """
    return [get_socket(port) for port in ports]


def get_connected_socket(sockets):
    """ If one of the sockets has an incoming connection, accept it. """


if __name__ == '__main__':
    port_numbers = get_ports()
    socket_ENG, socket_MAO, socket_GER = get_sockets(port_numbers)

    # socket_ENG.listen()
    # print(socket_ENG)
    #
    # connected_socket = None
    # while connected_socket is None:
    #     connected_socket = socket_ENG.accept()
    #
    # print(a)

    print("Server running on {}".format(socket_ENG.getsockname()[0]))
    print("ENG port: {}".format(socket_ENG.getsockname()[1]))
    print("MAO port: {}".format(socket_MAO.getsockname()[1]))
    print("GER port: {}".format(socket_GER.getsockname()[1]))

    while True:
        data, addr = socket_ENG.recvfrom(1024)
        print(data, addr)
