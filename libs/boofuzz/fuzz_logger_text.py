import sys

from colorama import init

from . import helpers, ifuzz_logger_backend

init()

DEFAULT_HEX_TO_STR = helpers.hex_to_hexstr


class FuzzLoggerText(ifuzz_logger_backend.IFuzzLoggerBackend):
    """
    This class formats FuzzLogger data for text presentation. It can be
    configured to output to STDOUT, or to a named file.

    Using two FuzzLoggerTexts, a FuzzLogger instance can be configured to output to
    both console and file.
    """
    
    INDENT_SIZE = 2

    def __init__(self, file_handle=sys.stdout, bytes_to_str=DEFAULT_HEX_TO_STR):
        """
        :type file_handle: io.BinaryIO
        :param file_handle: Open file handle for logging. Defaults to sys.stdout.

        :type bytes_to_str: function
        :param bytes_to_str: Function that converts sent/received bytes data to string for logging.
        """
        self._file_handle = file_handle
        self._format_raw_bytes = bytes_to_str

    def open_test_step(self, description):
        self._print_log_msg(msg=description, msg_type="step")

    def log_check(self, description):
        self._print_log_msg(msg=description, msg_type="check")

    def log_error(self, pkt_name, path, rawpkt):
        print("error: packet name: {}, path: {}, raw: {}".format(pkt_name, path, rawpkt))

    def log_recv(self, data):
        self._print_log_msg(data=data, msg_type="receive")

    def log_send(self, data):
        self._print_log_msg(data=data, msg_type="send")

    def log_info(self, description):
        print("info: {}".format(description))

    def open_test_case(self, name, cur_path):
        print("packet_name: {},path: {}".format( name, cur_path))

    def log_test_case(self, packet_name, rawpkt):
        print("packet_name: {},rawpkt: {}".format( packet_name, rawpkt))

    def log_fail(self, description=""):
        print("fail: {}".format(description))

    def log_pass(self, description=""):
        self._print_log_msg(msg=description, msg_type="pass")

    def close_test_case(self):
        pass

    def close_test(self):
        pass

    def _print_log_msg(self, msg_type, msg=None, data=None):
        print(
            helpers.format_log_msg(msg_type=msg_type, description=msg, data=data, indent_size=self.INDENT_SIZE),
            file=self._file_handle,
        )
