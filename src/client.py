import socket
import select
import sys
import re

MIN_PORT = 1024     # Inclusive
MAX_PORT = 64000    # Inclusive
MAGIC_NUMBER = 0x497E
DT_REQUEST_CODE = 0x0001
DT_RESPONSE_CODE = 0x0001
DATE_REQUEST_CODE = 0x0001
TIME_REQUEST_CODE = 0x0001


def check_num_parameters():
    """ Were all 3 parameters given when the program was run?
    If yes, do nothing
    If not, call an exception. """
    if len(sys.argv) < 4:
        raise Exception("Client needs 3 parameters! (info type, server IP, port")


def get_info_type_parameter():
    """ Get the info type parameter (parameter index 1).
    Checks that it is either "date", or "time". if it's neither, an exception is thrown.
    Assumes the parameter exists.

    Returns:
          (string) type of data the user asked for (either, "date" or "time")
    """
    info_type = sys.argv[1]
    if info_type not in ("date", "time"):
        raise Exception("""First parameter (info type) must be "date" or "time" """)
    return info_type


def get_ip_parameter():
    """ Get the ip parameter (parameter index 2) in dotted decimal form (string).
    Assumes the parameter exists.

    If the parameter is given in dotted decimal notation, return this
    If it's given as a textual addr (eg thing.that.nz), convert it to dotted decimal.

    Returns:
         (string) ip address the user want's to connect to in dotted decimal.
    """
    ip = sys.argv[2]
    if not is_in_dotted_decimal(ip):
        ip = get_dotted_decimal(ip)
    return ip


def is_in_dotted_decimal(addr):
    """ Is the addr in dotted decimal?
    in form "x1.x2.x3.x4" where x1 - x4 are integers between 0 and 255 (inclusive).

    Returns:
        (bool) wither the ip address is already in dotted decimal notation.
    """
    match = re.search("([0-9]{1,3}\.){3}[0-9]{1,3}", addr)
    if match is None:
        return False   # Failed format check
    # Are the xs between 0 and 255?
    for x in addr.split("."):
        if not 0 <= int(x) <= 255:
            return False    # Has number out of range
    return True     # has passed all checks


def get_dotted_decimal(addr):
    """ Given a address like thing.that.com, get it in dotted decimal
    uses socket.getaddrinfo with the addr and port parameter to obtain the ip address.

    Returns:
        (string): IPv4 address of addr (in dotted decimal)
    """
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
    """ get the port parameter (index 3).
    Check it's an integer and that it's between MIN_PORT and MAX_PORT (inclusive)

    Returns:
        (int) port user wants to connect to.
    """
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
    """ Get a new socket and connect it to server_ip and port.
    Returns:
        (socket) socket connected to server_ip and port
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)             # Create a socket object
    sock.connect((server_ip, port))
    return sock


def compose_request_packet(request_type):
    """ Get a formatted request packet with the packetType and requestType.

    To be a 6 byte bytearray where
      - 1st and 2nd bytes are the magic number
      - 3rd and 4th bytes are the packet type, this will be request (1)
      - 5th and 6th bytes are the request type. date = 1, time = 2

    Args:
        request_type (string): type of request, either "date" or "time".

    Returns:
        (bytearray) the packet made
    """
    if request_type == "date":
        request_type_int = DATE_REQUEST_CODE
    else:
        request_type_int = TIME_REQUEST_CODE
    magic_no_byte1 = MAGIC_NUMBER >> 8
    magic_no_byte2 = MAGIC_NUMBER & 0xFF
    return bytearray([magic_no_byte1, magic_no_byte2, 0, 1, 0, request_type_int])


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
    get_response_packet_info(packet)
    # magic_no, info_type, packet_type = get_request_packet_info(packet)
    #
    # if not check_request(magic_no, info_type, packet_type):
    #     # TODO Better messages pls
    #     print("Uh oh, this isn't a valid request packet!")
    #     return
    #
    # print("Request received")
    # response_packet = compose_response_packet(info_type)
    # sock.sendto(response_packet, source)
    # print("Sending response")
    # quit()


def get_response_packet_info(packet):
    """ Given a packet bytearray, extract the info from it.

    If the packet is the right length to be a response (23 bytes), return its info,
    If not, return None.

    Args:
        packet (bytearray): the received packet.

    Returns:
        (int) magic number from packet
        (int) packet type (should be 2 for response)
        (int) language code (1 = english, 2 = maori, 3 = german)
        (int) year
        (int) month (1 = jan, 2 = feb ... )
        (int) day (between 1 and 31 - inclusive)
        (int) hour (0 to 23 - inclusive)
        (int) minute (0 to 59 - inclusive)
        (int) length of text section in bytes
        (str) text field from packet
    """
    print(len(packet))
    if len(packet) < 13 * 8:    # 13 bytes is the header size
        return None
    magic_no = int(packet[0:16], base=2)
    packet_type = int(packet[16:32], base=2)
    language_code = int(packet[32:48], base=2)
    year = int(packet[48:64], base=2)
    month = int(packet[64:72], base=2)
    day = int(packet[72:80], base=2)
    hour = int(packet[80:88], base=2)
    minute = int(packet[88:96], base=2)
    length = int(packet[96:104], base=2)
    return magic_no, packet_type, language_code, year, month, day, hour, minute, length, "ass"


if __name__ == '__main__':
    check_num_parameters()
    ip = get_ip_parameter()
    port = get_port_parameter()
    info_type = get_info_type_parameter()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("Connected to {} on port {}".format(ip, port))

    request_packet = compose_request_packet(info_type)
    sock.sendto(request_packet, (ip, port))

    inputs = [sock]
    outputs = []
    message_queues = {}

    while inputs:
        readable, writable, exceptional = select.select(inputs, outputs, inputs)
        handle_readable(readable)
