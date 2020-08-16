import socket
import select
import sys
import re

MIN_PORT = 1024     # Inclusive
MAX_PORT = 64000    # Inclusive

DATE_REQUEST_CODE = 0x0001
TIME_REQUEST_CODE = 0x0002


class DateClient:

    MAGIC_NUMBER = 0x497E
    DT_REQUEST_CODE = 0x0001
    DT_RESPONSE_CODE = 0x0002
    DATE_REQUEST_CODE = 0x0001
    TIME_REQUEST_CODE = 0x0002

    def get_date_time(self, request_type, addr, port, timeout=1):
        """ Get the info from the server at addr on port.
        Blocks until a response is received (or times out).

        if a valid response is found, return a big tuple of the info
        if not, return None

        Args:
            request_type (int): what are we requesting? eg. DateClient.TIME_REQUEST_CODE
            addr (str): ip address in dotted decimal
            port (int): port to connect to
            timeout (float): timeout of the connection
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Send a request packet
        sock.sendto(self.compose_request_packet(request_type), (addr, port))

        # Wait for response
        packet = None
        readable, writable, exceptional = select.select([sock], [], [sock], timeout)
        for item in readable:
            packet_info = self.handle_readable(item)
            if packet_info is not None:
                packet = packet_info
                break
        sock.close()
        return packet

    def compose_request_packet(self, request_type):
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
        magic_no_byte1 = self.MAGIC_NUMBER >> 8
        magic_no_byte2 = self.MAGIC_NUMBER & 0xFF
        return bytearray([magic_no_byte1, magic_no_byte2, 0, 1, 0, request_type])

    def handle_readable(self, readable):
        """ Handle a incoming packet.
        if packet is a valid response, return a big tuple of the info
        if packet is not a valid response, return None

        Args:
            readable (list): list of readable incoming things, given by select.select
        Returns:
            (tuple): all the info from the packet in a tuple, info specified in assignment,
        """
        if isinstance(readable, socket.socket):
            packet, source = readable.recvfrom(1024)
            return self.process_response_packet(packet)

    def process_response_packet(self, packet):
        """ Given a packet, check if it's a request packet,
        if the packet is a request, process it and send back the response.

        Args:
            packet (bytearray): The received packet
        """
        if len(packet) < 13:    # 13 bytes is the header size
            print("Got response that was too small")

        magic_no = packet[0] << 8 | packet[1]
        packet_type = packet[2] << 8 | packet[3]
        language_code = packet[4] << 8 | packet[5]
        year = packet[6] << 8 | packet[7]
        month = packet[8]
        day = packet[9]
        hour = packet[10]
        minute = packet[11]
        length = packet[12]
        text = packet[13:].decode("utf-8")

        self.check_response(magic_no, packet_type, language_code, year, month, day, hour, minute, length, text)
        return magic_no, packet_type, language_code, year, month, day, hour, minute, length, text

    def check_response(self, magic_no, packet_type, language_code, year, month, day, hour, minute, length, text):
        """ Check the info received from the packet.
        Checks specified in assignment doc.

        Spit out message with why things are wrong if they are wrong

        Return:
            (bool): whether response is valid
        """
        if magic_no != self.MAGIC_NUMBER:
            print("Got response with wrong magic number")
        elif packet_type != self.DT_RESPONSE_CODE:
            print("Got response with wrong packet_type")
        elif language_code not in [1, 2, 3]:  # 1 = eng, 2 = mao, 3 = ger
            print("Got response with invalid language code")
        elif year < 0:
            print("Got response with invalid year")
        elif not 1 <= month <= 12:
            print("Got response with invalid month")
        elif not 1 <= day <= 31:
            print("Got response with invalid day")
        elif not 0 <= hour <= 23:
            print("Got response with invalid hour")
        elif not 0 <= minute <= 59:
            print("Got response with invalid hour")
        elif not len(text) == length:
            print("Got response with incorrect length")
        else:
            return True
        return False


def check_num_parameters():
    """ Were all 3 parameters given when the program was run?
    If yes, do nothing
    If not, call an exception. """
    if len(sys.argv) < 4:
        raise Exception("Client needs 3 parameters! (info type, server IP, port)")


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


def get_addr_parameter():
    """ Get the ip parameter (parameter index 2) in dotted decimal form (string).
    Assumes the parameter exists.

    If the parameter is given in dotted decimal notation, return this
    If it's given as a textual addr (eg thing.that.nz), convert it to dotted decimal.

    Returns:
         (string) ip address the user want's to connect to in dotted decimal.
    """
    addr = sys.argv[2]
    if not is_in_dotted_decimal(addr):
        addr = get_dotted_decimal(addr)
    return addr


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


def print_formatted_info(info):
    """ Print out the info nicely.
    info is to be a tuple of the response packet. """
    print("""
Date: {}/{}/{}
Time: {}:{}
Text: {}""".format(info[5], info[4], info[3], info[6], info[7], info[9]))


if __name__ == '__main__':
    # Get parameters
    check_num_parameters()
    addr = get_addr_parameter()
    port = get_port_parameter()
    info_type = get_info_type_parameter()

    if info_type == "date":
        info_type_int = DateClient.DATE_REQUEST_CODE
    else:
        info_type_int = DateClient.TIME_REQUEST_CODE

    # Send request and get the response
    client = DateClient()
    info = client.get_date_time(info_type_int, addr, port)
    if info is None:
        raise Exception("No response packet received.")
    else:
        print_formatted_info(info)

