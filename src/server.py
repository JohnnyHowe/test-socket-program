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
        self.TIME_REQUEST_CODE = 0x0002

        self.ip = socket.gethostbyname(socket.gethostname())

        self.ENG_CODE = 1
        self.MAO_CODE = 2
        self.GER_CODE = 3

        self.TEXT_FORMATS = {
            self.TIME_REQUEST_CODE: {
                self.ENG_CODE: "The current time is {0}:{1}",
                self.MAO_CODE: "Ko te wa o tenei wa {0}:{1}",
                self.GER_CODE: "Die Uhrzeit ist {0}:{1}",
            },
            self.DATE_REQUEST_CODE: {
                self.ENG_CODE: "Today's date is {2} {3}, {4}",
                self.MAO_CODE: "Ko te ra o tenei ra ko {2} {3}, {4}",
                self.GER_CODE: "Heute ist der {2}. {3} {4}"
            }
        }

        self.MONTHS = {
            self.ENG_CODE: ["January", "February", "March", "April", "May", "June", "July",
                            "August", "September", "October", "November", "December"],
            self.MAO_CODE: ["Kohi-tātea", "Hui-tanguru", "Poutū-te-rangi", "Paenga-whāwhā",
                            "Haratua", "Pipiri", "Hongonui", "Here-turi-kōkā", "Mahuru",
                            "Whiringa-ā-nuku", "Whiringa-ā-rangi", "Hakihea"],
            self.GER_CODE: ["Januar", "Februar", "März", "April", "Mai", "Juni", "Juli",
                            "August", "September", "Oktober", "November", "Dezember"],
        }

        self.ports = {
            self.ENG_CODE: eng_port,
            self.MAO_CODE: mao_port,
            self.GER_CODE: ger_port,
        }
        self.language_codes = {v: k for k, v in self.ports.items()}      # Reverse ports dict

        self.sockets = {}
        for code in [self.ENG_CODE, self.MAO_CODE, self.GER_CODE]:
            self.sockets[code] = self.get_socket(self.ports[code])

    def get_socket(self, port):
        """ Get a new socket bound to this machine and port. """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.ip, port))
        sock.setblocking(False)
        return sock

    def run(self):
        """ Run the server. Is blocking.
        If one of the sockets receives a request packet, send back the info. """
        inputs = [self.sockets[self.ENG_CODE], self.sockets[self.MAO_CODE], self.sockets[self.GER_CODE]]
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
            magic_no, packet_type, request_type = packet_info

        if not self.check_request(magic_no, packet_type, request_type):
            print("Got a packet that wasn't a valid request.")
            return

        port = sock.getsockname()[1]
        response_packet = self.compose_response_packet(request_type, self.language_codes[port])
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

    def compose_response_packet(self, request_type, language_code):
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

        Args:
            request_type (int): what is the user requesting? (TIME_REQUEST_CODE vs DATE_...)
            language_code (int): what language?

        Returns:
            (bytearray): packet made
        """
        today = datetime.datetime.today()

        text = self.TEXT_FORMATS[request_type][language_code].format(today.hour, today.minute, self.MONTHS[language_code][today.month - 1], today.day, today.year)
        text_array = bytearray(text, "utf-8")

        magic_no_byte1 = self.MAGIC_NUMBER >> 8
        magic_no_byte2 = self.MAGIC_NUMBER & 0xFF
        packet_list = [
            magic_no_byte1, magic_no_byte2,
            0, self.DT_RESPONSE_CODE,
            0, language_code,
            today.year >> 8, today.year & 0xFF,
            today.month, today.day,
            today.hour, today.minute,
            len(text_array),
        ]
        return bytearray(packet_list) + text_array


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

