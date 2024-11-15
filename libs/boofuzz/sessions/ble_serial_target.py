import time
from Ble_Test.driver.NRF52_dongle import *
from boofuzz import exception

from Ble_Test.packet.sul_interface_normal import *


class BLESerialTarget():
    """
    ITargetConnection implementation for generic serial ports.

    Since serial ports provide no default functionality for separating messages/packets, this class provides
    several means:

    * timeout: Return received bytes after timeout seconds.
    * msg_separator_time:
      Return received bytes after the wire is silent for a given time.
      This is useful, e.g., for terminal protocols without a machine-readable delimiter.
      A response may take a long time to send its information, and you know the message is done
      when data stops coming.
    * content_check:
      A user-defined function takes the data received so far and checks for a packet.
      The function should return 0 if the packet isn't finished yet, or n if a valid message of n
      bytes has been received. Remaining bytes are stored for next call to recv(). Example: ::

           def content_check_newline(data):
           if data.find('\\n') >= 0:
               return data.find('\\n')
           else:
               return 0

    If none of these methods are used, your connection may hang forever.

    .. versionchanged:: 0.2.0
        SerialConnection has been moved into the connections subpackage.
        The full path is now boofuzz.connections.serial_connection.SerialConnection

    Args:
        port (Union[int, str]): Serial port name or number.
        baudrate (int): Baud rate for port.
        timeout (float): For recv(). After timeout seconds from receive start, recv() will return all received data,
            if any.
        message_separator_time (float): After message_separator_time seconds *without receiving any more data*,
            recv() will return. Optional. Default None.
        content_checker (function(str) -> int): User-defined function. recv() will pass all bytes received so far to
            this method. If the method returns n > 0, recv() will return n bytes. If it returns 0, recv() will keep on
            reading.
    """

    def __init__(self, sul_interface = None,timeout=5, message_separator_time=4, content_checker=None):
        self._connection = sul_interface
        self.timeout = timeout
        self.message_separator_time = message_separator_time
        self.content_checker = content_checker
        self._data = bytes()

    def close(self,callback):
        """
        Close connection to the target.

        :return: None
        """
        # 关闭设备 terminal_ind

    def open(self,callback):
        """
        Opens connection to the target. Make sure to call close!

        :return: None
        """
        # callback()
        # 设备扫描scan req
        
        

    def recv(self):

        # self._connection.timeout = min(1, self.message_separator_time, self.timeout)

        start_time = last_byte_time = time.time()
        received_data_set = {}

        while True:
            # Update timer for message_separator_time
            if self._data:
                last_byte_time = time.time()
            else:
                pass

            # Try recv 
            self._data = self._connection.raw_receive()
            if self._data:

                # User-supplied content_checker function
                if self.content_checker is not None:
                    received_data = self.content_checker(self._data)
                    received_data_set.update(received_data)

            # Check timeout and message_separator_time
            cur_time = time.time()
            if self.timeout is not None and cur_time - start_time >= self.timeout:
                break
            if self.message_separator_time is not None and cur_time - last_byte_time >= self.message_separator_time:
                raise exception.BoofuzzTargetConnectionFailedError
        
            time.sleep(0.01)

    def send(self, pkt):
        """
        Send data to the target. Only valid after calling open!

        Args:
            data: Data to send.

        Returns:
            int: Number of bytes actually sent.
        """
        num_sent = 0    

        try:
            self._connection.raw_send(pkt)
        except:
            raise exception.BLESerialTargetReset()
    


    @property
    def info(self):
        return "port: {port}, baudrate: {baudrate}".format(port=self._port, baudrate=self._baudrate)
