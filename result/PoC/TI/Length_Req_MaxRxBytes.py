import os

import sys
from time import sleep

 
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../../")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../libs/")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../libs/boofuzz/")
# sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/libs/aalpy/")
# sys.path.append(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/srcs/")




from Ble_Test.packet.read_config import *
from Ble_Test.driver.NRF52_dongle import NRF52Dongle
from scapy.compat import raw
from boofuzz.primitives.bit_field import Bit_Field
from scapy.volatile import *

from scapy.utils import hexdump
from scapy.layers.bluetooth4LE import *
from scapy.layers.inet6 import *
from scapy.layers.bluetooth import *
from scapy.fields import *
from scapy.packet import fuzz
from scapy.all import *
from colorama import Fore




# from Ble_Test.srcs.Send_Packet.BLE_LL import BLE_LL
# from Ble_Test.srcs.Send_Packet.BLE_L2CAP import BLE_L2CAP

# from aalpy.utils import load_automaton_from_file
# import networkx as nx
# import matplotlib.pyplot as plt

from Ble_Test.srcs.State_Machine.Bluetooth_SUL import Bluetooth_SUL
# from Ble_Test.libs.boofuzz.blocks import block
from Ble_Test.libs.boofuzz.primitives import *

from Ble_Test.srcs.Log_Config.logger_config import *


from Ble_Test.srcs.Config_File.TI import config

str = config.device["advertiser_address"]
Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_legency_pkts",6:"test_sc_pkts"}
# ll = AutomataSUL_Graph('/home/yangting/Documents/Ble_state_check/result/pairing_select_05_28.dot')
# graph = ll.mealy_to_graph()
# print(graph.nodes)
# path = ll.find_all_paths(graph)
# print("-------------------")
# print(len(path))
advertiser_address = config.device["advertiser_address"]
iat = config.device["iat"]
rat = config.device["rat"]
role = config.device["role"]
rx_len = config.device["rx_len"]
tx_len = config.device["tx_len"]
test_layer = Layers[config.device["packet_layer"]]
config_file = config.device["config_file"]

return_handle_layer = [Layers[i] for i in config.device["return_handle_layer"]]
send_handle_layer = [Layers[i] for i in config.device["send_handle_layer"]]
port_name = config.device["port_name"]
logs_pcap = config.device["logs_pcap"]
pcap_filename = config.device["pcap_filename"]
if config.device["return_handle_layer"]:
    for i in config.device["return_handle_layer"]:
        return_handle_layer.append(Layers[int(i)])
logger_handle = config_file.split('/')[-1].split('.')[0]

logger = configure_logger( logger_handle, config.device["log_path"],logging.DEBUG)
key_path = config.device["key_path"]


# 获取log配置
ble_sul = Bluetooth_SUL(NRF52Dongle(port_name=port_name,logs_pcap=logs_pcap,pcap_filename=pcap_filename), advertiser_address, iat,rat,role,rx_len,tx_len, logger_handle, key_path,test_layer, config_file, return_handle_layer=return_handle_layer,send_handle_layer=send_handle_layer)


ble_sul.pre()

pkt = ble_sul.get_packet("ll_feature_req_pkt")
pkt.show2()
ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

pkt = ble_sul.get_packet("ll_length_req_pkt")
# set max rx bytes and max tx bytes
pkt["LL_LENGTH_REQ"].max_rx_bytes = 5
pkt["LL_LENGTH_REQ"].max_tx_bytes = 5 
pkt.show2()
ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

pkt = ble_sul.get_packet("ll_version_ind_pkt")
pkt.show2()
ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

pkt = ble_sul.get_packet("pairing_request_pkt")
# pkt.show2()
ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

pkt = ble_sul.get_packet("pairing_confirm_pkt")
# pkt.show2()
ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

pkt = ble_sul.get_packet("pairing_random_pkt")
# pkt.show2()
ble_sul.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 10,connect_max_attempts = 50)

