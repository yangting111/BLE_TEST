import errno
import importlib.metadata
import os
import re
import signal
import socket
import struct
import time
import warnings
import zlib
from builtins import int
from functools import reduce

from colorama import Back, Fore, Style

from .connections import ip_constants, udp_socket_connection
from .exception import BoofuzzError

# Curses color pairs

COLOR_PAIR_WHITE = 1
COLOR_PAIR_CYAN = 2
COLOR_PAIR_RED = 3
COLOR_PAIR_YELLOW = 4
COLOR_PAIR_GREEN = 5
COLOR_PAIR_MAGENTA = 6
COLOR_PAIR_BLACK = 7

test_step_info = {
    "test_case": {
        "indent": 0,
        "title": "Test Case",
        "html": "Test Case: {msg}",
        "terminal": Fore.YELLOW + Style.BRIGHT + "Test Case: {msg}" + Style.RESET_ALL,
        "css_class": "log-case",
        "curses": COLOR_PAIR_YELLOW,
    },
    "step": {
        "indent": 1,
        "title": "Test Step",
        "html": " Test Step: {msg}",
        "terminal": Fore.MAGENTA + Style.BRIGHT + "Test Step: {msg}" + Style.RESET_ALL,
        "css_class": "log-step",
        "curses": COLOR_PAIR_MAGENTA,
    },
    "info": {
        "indent": 2,
        "title": "Info",
        "html": "Info: {msg}",
        "terminal": "Info: {msg}",
        "css_class": "log-info",
        "curses": COLOR_PAIR_WHITE,
    },
    "error": {
        "indent": 2,
        "title": "Error",
        "html": "Error!!!! {msg}",
        "terminal": Back.RED + Style.BRIGHT + "Error!!!! {msg}" + Style.RESET_ALL,
        "css_class": "log-error",
        "curses": COLOR_PAIR_RED,
    },
    "send": {
        "indent": 2,
        "title": "Transmitted",
        "html": "Transmitted {n} bytes{note}: {msg}",
        "terminal": Fore.CYAN + "Transmitted {n} bytes{note}: {msg}" + Style.RESET_ALL,
        "css_class": "log-send",
        "curses": COLOR_PAIR_CYAN,
    },
    "receive": {
        "indent": 2,
        "title": "Received",
        "html": "Received{note}: {msg}",
        "terminal": Fore.CYAN + "Received{note}: {msg}" + Style.RESET_ALL,
        "css_class": "log-receive",
        "curses": COLOR_PAIR_CYAN,
    },
    "check": {
        "indent": 2,
        "title": "Check",
        "html": "Check: {msg}",
        "terminal": "Check: {msg}",
        "css_class": "log-check",
        "curses": COLOR_PAIR_WHITE,
    },
    "fail": {
        "indent": 3,
        "title": "Check Failed",
        "html": "Check Failed: {msg}",
        "terminal": Fore.RED + Style.BRIGHT + "Check Failed: {msg}" + Style.RESET_ALL,
        "css_class": "log-fail",
        "curses": COLOR_PAIR_RED,
    },
    "pass": {
        "indent": 3,
        "title": "Check OK",
        "html": "Check OK: {msg}",
        "terminal": Fore.GREEN + Style.BRIGHT + "Check OK: {msg}" + Style.RESET_ALL,
        "css_class": "log-pass",
        "curses": COLOR_PAIR_GREEN,
    },
}


def ip_str_to_bytes(ip):
    """Convert an IP string to a four-byte bytes.

    :param ip: IP address string, e.g. '127.0.0.1'

    :return 4-byte representation of ip, e.g. b'\x7F\x00\x00\x01'
    :rtype bytes

    :raises ValueError if ip is not a legal IP address.
    """
    try:
        return socket.inet_aton(ip)
    except socket.error:
        raise ValueError("Illegal IP address passed to socket.inet_aton: {0}".format(ip))


def get_max_udp_size():
    """
    Crazy CTypes magic to do a getsockopt() which determines the max UDP payload size in a platform-agnostic way.

    .. deprecated:: 0.2.0
        Use :meth:`UDPSocketConnection.max_payload() <boofuzz.connections.UDPSocketConnection.max_payload>` instead.

    Returns:
        int: The maximum length of a UDP packet the current platform supports
    """
    warnings.warn(
        "get_max_udp_size() is deprecated and will be removed in a future version of boofuzz. "
        "Use UDPSocketConnection.max_payload() instead.",
        FutureWarning,
    )

    return udp_socket_connection.UDPSocketConnection.max_payload()


def calculate_four_byte_padding(string, character="\x00"):
    return character * ((4 - (len(string) & 3)) & 3)


def crc16(string, value=0):
    """CRC-16 poly: p(x) = x**16 + x**15 + x**2 + 1

    @param string: Data over which to calculate crc.
    @param value: Initial CRC value.
    """
    crc16_table = []
    for byte in range(256):
        crc = 0

        for _ in range(8):
            if (byte ^ crc) & 1:
                crc = (crc >> 1) ^ 0xA001  # polly
            else:
                crc >>= 1

            byte >>= 1

        crc16_table.append(crc)

    for ch in string:
        value = crc16_table[ord(ch) ^ (value & 0xFF)] ^ (value >> 8)

    return value


def crc32(string):
    return zlib.crc32(string) & 0xFFFFFFFF


def uuid_bin_to_str(uuid):
    """Convert a binary UUID to human readable string.

    @param uuid: bytes representing UUID.
    """
    (block1, block2, block3) = struct.unpack("<LHH", uuid[:8])
    (block4, block5, block6) = struct.unpack(">HHL", uuid[8:16])

    return "%08x-%04x-%04x-%04x-%04x%08x" % (block1, block2, block3, block4, block5, block6)


def uuid_str_to_bin(uuid):
    """
    Converts a UUID string to binary form.

    Expected string input format is same as uuid_bin_to_str()'s output format.

    Ripped from Core Impacket.

    :param uuid: UUID string to convert to bytes.
    :type uuid: str
    :return: UUID as bytes.
    :rtype: bytes
    """
    uuid_re = r"([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})"

    matches = re.match(uuid_re, uuid)

    # pytype: disable=attribute-error
    (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6) = map(lambda x: int(x, 16), matches.groups())
    # pytype: enable=attribute-error

    uuid = struct.pack("<LHH", uuid1, uuid2, uuid3)
    uuid += struct.pack(">HHL", uuid4, uuid5, uuid6)

    return uuid


def _ones_complement_sum_carry_16(a, b):
    """Compute ones complement sum and carry at 16 bits.

    :type a: int
    :type b: int

    :return: Sum of a and b, ones complement, carry at 16 bits.
    """
    pre_sum = a + b
    return (pre_sum & 0xFFFF) + (pre_sum >> 16)


def _collate_bytes(msb, lsb):
    """
    Helper function for our helper functions.
    Collates msb and lsb into one 16-bit value.

    :type msb: byte
    :param msb: Single byte (most significant).

    :type lsb: byte
    :param lsb: Single byte (least significant).

    :return: msb and lsb all together in one 16 bit value.
    """
    return (msb << 8) + lsb


def ipv4_checksum(msg):
    """
    Return IPv4 checksum of msg.
    :param msg: Message to compute checksum over.
    :type msg: bytes

    :return: IPv4 checksum of msg.
    :rtype: int
    """
    # Pad with 0 byte if needed
    if len(msg) % 2 == 1:
        msg += b"\x00"

    msg_words = map(_collate_bytes, msg[0::2], msg[1::2])
    total = reduce(_ones_complement_sum_carry_16, msg_words, 0)
    return ~total & 0xFFFF


def _udp_checksum_pseudo_header(src_addr, dst_addr, msg_len):
    """Return pseudo-header for UDP checksum.

    :type src_addr: bytes
    :param src_addr: Source IP address -- 4 bytes.

    :type dst_addr: bytes
    :param dst_addr: Destination IP address -- 4 bytes.

    :param msg_len: Length of UDP message (not including IPv4 header).
    :type msg_len: int

    :return: UDP pseudo-header
    :rtype: bytes
    """
    return src_addr + dst_addr + b"\x00" + bytes([ip_constants.IPV4_PROTOCOL_UDP]) + struct.pack(">H", msg_len)


def udp_checksum(msg, src_addr, dst_addr):
    """Return UDP checksum of msg.

    Recall that the UDP checksum involves creating a sort of pseudo IP header.
    This header requires the source and destination IP addresses, which this
    function takes as parameters.

    If msg is too big, the checksum is undefined, and this method will
    truncate it for the sake of checksum calculation. Note that this means the
    checksum will be invalid. This loosey goosey error checking is done to
    support fuzz tests which at times generate huge, invalid packets.


    :param msg: Message to compute checksum over.
    :type msg: bytes

    :type src_addr: bytes
    :param src_addr: Source IP address -- 4 bytes.
    :type dst_addr: bytes
    :param dst_addr: Destination IP address -- 4 bytes.

    :return: UDP checksum of msg.
    :rtype: int
    """
    # If the packet is too big, the checksum is undefined since len(msg)
    # won't fit into two bytes. So we just pick our best definition.
    # "Truncate" the message as it appears in the checksum.
    msg = msg[0 : ip_constants.UDP_MAX_LENGTH_THEORETICAL]

    return ipv4_checksum(_udp_checksum_pseudo_header(src_addr, dst_addr, len(msg)) + msg)


def hex_str(s):
    """
    Returns a hex-formatted string based on s.

    Args:
        s (bytes): Some string.

    Returns:
        str: Hex-formatted string representing s.
    """
    return " ".join("{:02x}".format(b) for b in bytearray(s))


def pause_for_signal():
    """
    Pauses the current thread in a way that can still receive signals like SIGINT from Ctrl+C.

    Implementation notes:
     - Linux uses signal.pause()
     - Windows uses a loop that sleeps for 1 ms at a time, allowing signals
       to interrupt the thread fairly quickly.

    :return: None
    :rtype: None
    """
    try:
        while True:
            signal.pause()
    except AttributeError:
        # signal.pause() is missing for Windows; wait 1ms and loop instead
        while True:
            time.sleep(0.001)


def get_time_stamp():
    t = time.time()
    s = time.strftime("[%Y-%m-%d %H:%M:%S", time.localtime(t))
    s += ",%03d]" % (t * 1000 % 1000)
    return s


def _indent_all_lines(lines, amount, ch=" "):
    padding = amount * ch
    return padding + ("\n" + padding).join(lines.split("\n"))


def _indent_after_first_line(lines, amount, ch=" "):
    padding = amount * ch
    return ("\n" + padding).join(lines.split("\n"))


def format_log_msg(
    msg_type, description=None, data=None, indent_size=2, timestamp=None, truncated=False, format_type="terminal"
):
    curses_mode = False
    if data is None:
        data = b""
    if timestamp is None:
        timestamp = get_time_stamp()
    if format_type == "curses":
        curses_mode = True
        format_type = "html"

    if description is not None and description != "":
        msg = description
    elif data is not None and len(data) > 0:
        msg = hex_to_hexstr(input_bytes=data)
    else:
        msg = ""

    msg = test_step_info[msg_type][format_type].format(  # pytype: disable=attribute-error
        msg=msg, n=len(data), note="" if not truncated else " (data truncated for database storage)"
    )
    msg = _indent_all_lines(msg, (test_step_info[msg_type]["indent"]) * indent_size)
    msg = timestamp + " " + _indent_after_first_line(msg, len(timestamp) + 1)

    if curses_mode:
        return [msg, test_step_info[msg_type]["curses"]]

    return msg


def format_msg(msg, indent_level, indent_size, timestamp=None):
    msg = _indent_all_lines(msg, indent_level * indent_size)
    if timestamp is None:
        timestamp = get_time_stamp()
    return timestamp + " " + _indent_after_first_line(msg, len(timestamp) + 1)


def hex_to_hexstr(input_bytes):
    """
    Render input_bytes as ASCII-encoded hex bytes, followed by a best effort
    utf-8 rendering.

    Args:
        input_bytes (bytes): Arbitrary bytes

    Returns:
        str: Printable string
    """
    return hex_str(input_bytes) + " " + repr(input_bytes)


def mkdir_safe(directory_name, file_included=False):
    """Creates directory_name and subdirectories. If file_included is true, removes final element of the path"""
    if file_included:
        fullpath = os.path.abspath(directory_name)
        directory_name = os.path.dirname(fullpath)
    try:
        os.makedirs(directory_name)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def path_exists(path):
    """To avoid polluting files with import os"""
    return os.path.exists(path)


def get_boofuzz_version():
    """
    Gets the currently installed boofuzz version

    :rtype: str
    :return: Boofuzz version as string
    """
    return "v" + importlib.metadata.version("boofuzz")


def str_to_bytes(value, encoding="utf-8", errors="replace"):
    if isinstance(value, bytes):
        return value
    return value.encode(encoding, errors)


def parse_target(target_name):
    try:
        host, ip = target_name.split(":")
        return host, int(ip)
    except ValueError:
        raise ValueError("Target format is HOST:PORT")


def parse_test_case_name(test_case):
    """Parse a test case name into a message path and a list of mutation names.

    Example:
        Input: "message1:[message1.first_byte:2, message1.second_byte:1, message1.third_byte:2]"
        Output: ["message1"], ["message1.first_byte:2", "message1.second_byte:1", "message1.third_byte:2"]

    Returns:
        A message path (list of message names) and a list of mutation names.
    """
    components = test_case.split(":", 1)
    message_path = components[0]
    path = re.split("->", message_path)
    if len(components) < 2:
        return path, []
    else:
        mutations = components[1]
        match = re.match(r"\[(.*)\]", mutations)
        if match is None:
            raise BoofuzzError("could not parse test case name: {0}".format(test_case))
        mutations = match.group(1)
        mutations = re.split(r",\s*", mutations)
        return path, mutations
