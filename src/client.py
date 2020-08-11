import socket
import sys
import re

MIN_PORT = 1024     # Inclusive
MAX_PORT = 64000    # Inclusive

MAGIC_NUMBER = 0x497E


def check_num_parameters():
    """ Were all 3 parameters given when the program was run?
    If yes, do nothing
    If not, call an exception. """
    if len(sys.argv) < 4:
        raise Exception("Client needs 3 parameters! (info type, server IP, port")


def get_info_type_parameter():
    """ Return the info type parameter (parameter index 1).
    Assumes the parameter exists.
    Checks that it is either "date", or "time" - a exception is raised if it's not. """
    info_type = sys.argv[1]
    if info_type not in ("date", "time"):
        raise Exception("""First parameter (info type) must be "date" or "time" """)
    return info_type


def get_ip_parameter():
    """ Return the ip parameter (parameter index 2).
    Assumes the parameter exists.

    If the parameter is given in dotted decimal notation, return this

    If it's given as a textual addr (eg thing.that.nz), convert it to dotted decimal with
    getaddrinfo. """
    ip = sys.argv[2]
    if not is_in_dotted_decimal(ip):
        ip = get_dotted_decimal(ip)
    return ip


def is_in_dotted_decimal(addr):
    """ Is the addr in dotted decimal?
    in form "x1.x2.x3.x4" where x1 - x4 are integers between 0 and 255 (inclusive). """
    match = re.search("([0-9]{1,3}\.){3}[0-9]{1,3}", addr)
    if match is None:
        return False   # Failed format check
    # Are the xs between 0 and 255?
    for x in addr.split("."):
        if not 0 <= int(x) <= 255:
            return False    # Has number out of range
    return True     # has passed all checks


def get_dotted_decimal(addr):
    """ Given a address like thing.that.com - get it in dotted decimal """
    # return socket.getaddrinfo(addr, get_port_parameter())
    addr_info = socket.getaddrinfo(addr, get_port_parameter())
    ipv4_info = None
    for info in addr_info:
        if info[0] == socket.AF_INET:
            ipv4_info = info
            break
    if ipv4_info is None:
        # TODO fix exception
        raise Exception("Couldn't find an IPv4 thing!")
    else:
        ip, port = ipv4_info[4]
        return ip


def get_port_parameter():
    """ Return the port parameter (index 3).
    Check it's an integer and that it's between MIN_PORT and MAX_PORT (inclusive) """
    port_str = sys.argv[3]
    try:
        port = int(port_str)
    except ValueError as error:
        print("Port needs to be an integer!")
        print(error)
    if not MIN_PORT <= port <= MAX_PORT:
        raise Exception("Port must be between {} and {}".format(MIN_PORT, MAX_PORT))
    return port


def get_connected_socket(server_ip, port):
    """ Get a new socket and connect it to server_ip and port. """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)             # Create a socket object
    sock.connect((server_ip, port))
    return sock


def make_packet(packetType, requestType):
    """ Get a formatted packet with the packetType and requestType.

    Args:
        packetType (String): The type of packet to send, either "date" or "time".
        TODO finish this doc
    """


if __name__ == '__main__':
    check_num_parameters()
    ip = get_ip_parameter()
    port = get_port_parameter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("Connected to {} on port {}".format(ip, port))

    packet = bytearray(input("msg: "), "utf-8")
    sock.sendto(packet, (ip, port))
