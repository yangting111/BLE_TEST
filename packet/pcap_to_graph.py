import sys
import os

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/libs/")

from scapy.utils import RawPcapReader

#获得相关的信息例如address


def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    count = 0
    for (pkt_data, pkt_metadata) in RawPcapReader(file_name):

        count += 1
        if count == 1:
            print('Packet #1')
            print(pkt_metadata)
            print(pkt_data)
            break

    print('{} contains {} packets'.format(file_name, count))

if __name__ == '__main__':
    process_pcap('/home/yangting/Documents/Ble_Test/packet/esp32-provision-01.pcapng')