#！/usr/bin/env python
import os
import configparser
from scapy.all import rdpcap,raw
packet_dict = {}

def packet_to_dict(config_file,pcap_file):
    global packet_dict
    # 读取配置文件
    p = rdpcap(pcap_file)
    configread = configparser.ConfigParser()
    configread.read(config_file)
    for key in configread.options('input'):
        packet_dict[key] = raw(p[configread.getint('input', key)-1])
    
def change_packet(key,callback):
    pkt = packet_dict[key]
    key,value = callback(pkt)
    packet_dict[key] = value

def get_packet(packet):
    global packet_dict
    return packet_dict[packet]




