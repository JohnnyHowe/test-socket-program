import sys
import select
import socket

MIN_PORT = 1024     # Inclusive
MAX_PORT = 64000    # Inclusive
MAGIC_NUMBER = 0x497E
DT_REQUEST_CODE = 0x0001
DT_RESPONSE_CODE = 0x0001
DATE_REQUEST_CODE = 0x0001
TIME_REQUEST_CODE = 0x0001

NUM_PORTS = 3


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
        raise Exception("Server needs {} ports!".format(NUM_PORTS))
    return ports


def get_socket(port):
    """ Get a new socket bound to this machine and port. """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    host = socket.gethostbyname(socket.gethostname())
    sock.bind((host, port))
    sock.setblocking(False)
    return sock


def get_sockets(ports):
    """ Get a socket for each port. """
    return [get_socket(port) for port in ports]


def handle_readable(readable):
    """ Handle the incoming packets.
    Given a list of readable sockets, read the data and process it accordingly
    TODO what does that mean

    Args:
        readable (list): list of readable incoming things, given by select.select
    """
    for sock in readable:
        if isinstance(sock, socket.socket):
            packet, source = sock.recvfrom(1024)
            process_packet(packet, sock, source)
        else:
            raise Exception("Got something that isn't a socket")


def process_packet(packet, sock, source):
    """ Given a packet, check if it's a request packet,
    if the packet is a request, process it and send back the response.

    Args:
        packet (bytearray): The received packet
        sock (socket): socket the packet was received from
        source (tuple): TODO
    """
    packet_info = get_request_packet_info(packet)
    if packet_info is None:
        raise Exception("Didn't like that")
    else:
        magic_no, info_type, packet_type = packet_info

    if not check_request(magic_no, info_type, packet_type):
        # TODO Better messages pls
        print("Uh oh, this isn't a valid request packet!")
        quit()
        return

    print("Request received")
    response_packet = compose_response_packet(info_type)
    print("Sending response")
    sock.sendto(response_packet, source)
    quit()


def compose_response_packet(request_type):
    """ Compose a response packet in the order
        magic number (2 bytes),
        packet type (2 bytes),
        language code (2 bytes),
        year (2 bytes),
        month (1 byte),
        day (1 byte),
        hour (1 byte),
        minute (1 byte),
        length (1 byte),
        text ...
    """
    # TODO language code, time
    year = 0
    month = 0
    day = 0
    hour = 0
    minute = 0
    magic_no_byte1 = MAGIC_NUMBER >> 8
    magic_no_byte2 = MAGIC_NUMBER & 0xFF
    packet_list = [
        magic_no_byte1, magic_no_byte2,
        0, DT_RESPONSE_CODE,
        0, 1,
        0, year,
        month, day,
        hour, minute,
    ]
    return bytearray(packet_list)


def get_padded_bin_str(n, num_chars=16):
    """ Get the binary representation of the integer n padded with zeros at the beginning such
    that the string has a length of num_chars.

    Args:
        n (int): number to convert.
        num_chars (int): final string length

    Returns:
        (string) n as a binary string (num_chars long)
    """
    bin_n = bin(n)[2:]
    to_add = ((num_chars - len(bin_n)) % num_chars)
    return "0" * to_add + bin_n


def get_request_packet_info(packet):
    """ Given a packet bytearray, extract the info from it.

    If the packet is the right length to be a request (6 bytes), return its info,
    If not, return None.

    Args:
        packet (bytearray): the received packet.

    Returns:
        (int) magic number from packet
        (int) info type integer
        (int) packet type integer
    """
    if len(packet) != 6:
        return None
    magic_no = packet[0] << 8 | packet[1]
    info_type = packet[2] << 8 | packet[3]
    packet_type = packet[4] << 8 | packet[5]
    return magic_no, info_type, packet_type


def check_request(received_magic_no, packet_type, info_type):
    """ Is the given packet a valid request?

    is valid if:
        received_magic_no is MAGIC_NUMBER,
        packet_type = 1 (request)
        info_type is "date" or "time"

    Args:
        received_magic_no (int): the magic number from the received packet
        packet_type (int): the type of packet received (1 = request)
        info_type (int): 1 = date, 2 = time

    Returns:
        (bool) whether the info passes the checks
    """
    if received_magic_no != MAGIC_NUMBER:
        print(received_magic_no)
        return False
    elif packet_type != 1:
        return False
    elif info_type not in [1, 2]:
        return False
    else:
        return True


if __name__ == '__main__':
    port_numbers = get_ports()
    socket_ENG, socket_MAO, socket_GER = get_sockets(port_numbers)

    print("Server running on {}".format(socket_ENG.getsockname()[0]))
    print("ENG port: {}".format(socket_ENG.getsockname()[1]))
    print("MAO port: {}".format(socket_MAO.getsockname()[1]))
    print("GER port: {}".format(socket_GER.getsockname()[1]))

    inputs = [socket_ENG, socket_MAO, socket_GER]
    outputs = []
    message_queues = {}

    while inputs:
        readable, writable, exceptional = select.select(inputs, outputs, inputs)
        handle_readable(readable)

