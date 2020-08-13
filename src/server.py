import sys
import select
import socket
import datetime

MIN_PORT = 1024  # Inclusive
MAX_PORT = 64000  # Inclusive
NUM_PORTS = 3


class DateServer:
    """ Date server class.
    Given 3 ports it will listen on them and spit back date and time info.

    TODO more pls
    """
    def __init__(self, eng_port, mao_port, ger_port):
        self.MAGIC_NUMBER = 0x497E
        self.DT_REQUEST_CODE = 0x0001
        self.DT_RESPONSE_CODE = 0x0002
        self.DATE_REQUEST_CODE = 0x0001
        self.TIME_REQUEST_CODE = 0x0001

        self.ip = socket.gethostbyname(socket.gethostname())

        self.eng_port = eng_port
        self.mao_port = mao_port
        self.ger_port = ger_port

        self.eng_socket = self.get_socket(self.eng_port)
        self.mao_socket = self.get_socket(self.mao_port)
        self.ger_socket = self.get_socket(self.ger_port)

    def get_socket(self, port):
        """ Get a new socket bound to this machine and port. """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.ip, port))
        sock.setblocking(False)
        return sock

    def run(self):
        """ Run the server. Is blocking.
        If one of the sockets receives a request packet, send back the info. """
        inputs = [self.eng_socket, self.mao_socket, self.ger_socket]
        outputs = []
        while inputs:
            readable, writable, exceptional = select.select(inputs, outputs, inputs)
            for item in readable:
                self.handle_readable(item)

    def handle_readable(self, readable):
        """ Given a readable from select.select, handle it.
        If it's a socket with a request packet, check the value and return a response.  """
        if isinstance(readable, socket.socket):
            packet, source = readable.recvfrom(1024)
            self.process_packet(packet, readable, source)

    def process_packet(self, packet, sock, source):
        """ Given a packet, check if it's a request packet,
        if the packet is a request, process it and send back the response.

        Args:
            packet (bytearray): The received packet
            sock (socket): socket the packet was received from
            source (tuple): TODO
        """
        packet_info = self.get_request_packet_info(packet)
        if packet_info is None:
            print("Got a packet that wasn't a valid request.")
            return
        else:
            magic_no, info_type, packet_type = packet_info

        if not self.check_request(magic_no, info_type, packet_type):
            print("Got a packet that wasn't a valid request.")
            return

        response_packet = self.compose_response_packet(info_type)
        print("Valid packet received, sending response.")
        sock.sendto(response_packet, source)

    def check_request(self, received_magic_no, packet_type, info_type):
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
        if received_magic_no != self.MAGIC_NUMBER:
            return False
        elif packet_type != 1:
            return False
        elif info_type not in [1, 2]:
            return False
        else:
            return True

    def get_request_packet_info(self, packet):
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

    def compose_response_packet(self, request_type):
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
        today = datetime.datetime.today()
        magic_no_byte1 = self.MAGIC_NUMBER >> 8
        magic_no_byte2 = self.MAGIC_NUMBER & 0xFF
        language_code = 1
        packet_list = [
            magic_no_byte1, magic_no_byte2,
            0, self.DT_RESPONSE_CODE,
            0, language_code,
            today.year >> 8, today.year & 0xFF,
            today.month, today.day,
            today.hour, today.minute,
            0,
        ]
        return bytearray(packet_list)


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


if __name__ == '__main__':
    eng_port, mao_port, ger_port = get_ports()
    server = DateServer(eng_port, mao_port, ger_port)
    server.run()

