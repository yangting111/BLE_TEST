
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
# if master sul_type is 0, if slave sul_type is 1
# Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_legency_pkts",6:"test_sc_pkts",7:"test_all_pkts"}
device = {
    "advertiser_address": "9c:95:6e:40:0f:bb",
    "sul_type": 0,
    "iat": 1,
    "rat": 0,
    "role": 1,
    "rx_len": 251,
    "tx_len": 251,
    "packet_layer": 1,
    "config_file": "/home/yangting/Documents/Ble_state_check/srcs/Config_File/Microchip/pairing_select_05_28.ini",
    "learned_model_path": "/home/yangting/Documents/Ble_state_check/result/dot_file/Microchip/peripheral_all_test.dot",
    "model_path": "/home/yangting/Documents/Ble_state_check/result/dot_file/Microchip/pairing_sm_encryption_copy.dot",
    "log_path": "/home/yangting/Documents/Ble_state_check/result/log_file/Microchip/test.log",
    "port_name": "/dev/ttyACM0",
    "logs_pcap": True,
    "pcap_filename": "/home/yangting/Documents/Ble_state_check/result/log_file/Microchip/test_all.pcap",
    "return_handle_layer": [ 1, 3],
    "send_handle_layer": [1, 3],
    "key_path": "/home/yangting/Documents/Ble_state_check/result/log_file/Microchip/key.txt",
    "statepkt_dict": {"ll_base":['ll_feature_req_pkt', 'll_feature_rsp_pkt','ll_length_req_pkt', 'll_version_ind_pkt'],"sm_legency":['pairing_request_pkt','pairing_confirm_pkt', 'pairing_random_pkt', ],"sm_sc":['pairing_request_pkt','pairing_public_key_pkt',"pairing_random_pkt","pairing_dhkey_check_pkt"]},
}

statecheck = {
    "tested_letters_file" : "/home/yangting/Documents/Ble_state_check/result/log_file/Microchip/tested_letters.txt",
    "output_path": "/home/yangting/Documents/Ble_state_check/result/log_file/Microchip/output.txt",
}