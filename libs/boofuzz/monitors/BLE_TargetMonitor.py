import getopt  # command line arguments
import platform  # For getting the operating system name
import subprocess  # For executing a shell command
import sys
import time
from boofuzz.fuzz_logger_text import FuzzLoggerText
from Ble_Test.libs.scapy.compat import raw


mylogger = FuzzLoggerText()

class BLE_TargetMonitor():

    def __init__(self, target=None, fuzz_data_logger=None):
        self.target = target
        self.sulinterface = self.target._connection
        self.fuzz_data_logger = fuzz_data_logger
        self.detecte_alive_times = 5

    def alive(self):
        received = False
        for i in range(self.detecte_alive_times):
            received = self.sulinterface.scan_req_alive(timeout = 2)
            if received is True:
                return received
        return received
        
    def pre_send(self):
        return True

        
        
        
        

    def post_send(self):

        return True
    def stop(self):
        self.is_stop = True

    def retrieve_data():
        return

    def start_target(self):
        # 检测设备是否存活
        return self.alive()

    def set_options(*args, **kwargs):
        return

    def get_crash_synopsis():
        return "get_crash_synopsis detected a crash of the target."

    # The use of a 12 second sleep is based on experimentation for a specific IOT device. Change the number of seconds
    # as needed for your environment.
    def restart_target(self):
        self.target.send(raw(self.sulinterface.ll_termination_indication_pkt()))
        mylogger.log_info("restart_target sleep for 3")
        time.sleep(3)
        if self.alive() is True:
            mylogger.log_info("restart_target ok")
            return True
        else:
            mylogger.log_info("restart_target failed")
            return False

    def post_start_target(target=None, fuzz_data_logger=None, session=None, **kwargs):
        return

