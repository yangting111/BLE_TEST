

# if master sul_type is 0, if slave sul_type is 1
# Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_pkts"} 
device = {
    "advertiser_address": "50:54:7B:C4:D8:3C",
    "sul_type": 0,
    "iat": 1,
    "rat": 0,
    "role": 1,
    "rx_len": 251,
    "tx_len": 251,
    "packet_layer": 7,
    "config_file": "/home/yangting/Documents/Ble_Test/srcs/Config_File/WCH/esp_ble_security.ini",
    "learned_model_path": "/home/yangting/Documents/Ble_Test/result/dot_file/WCH/esp_ble_security_l2cap.dot",
    "log_path": "/home/yangting/Documents/Ble_Test/result/log_file/WCH/test_l2cap.log",
    "port_name": "/dev/ttyACM0",
    "logs_pcap": True,
    "pcap_filename": "/home/yangting/Documents/Ble_Test/result/log_file/WCH/test_smp_legency.pcap",
    "return_handle_layer": [1,3] ,
    "send_handle_layer":[1,3], # Uncomment and modify if needed
    "key_path": "/home/yangting/Documents/Ble_Test/result/log_file/WCH/key.txt",
    "statepkt_dict": {"ll_base":['ll_feature_req_pkt','ll_length_req_pkt', 'll_version_ind_pkt',],"sm_legency":['pairing_request_pkt','pairing_confirm_pkt', 'pairing_random_pkt', ],"sm_sc":['pairing_request_pkt','pairing_public_key_pkt',"pairing_random_pkt","pairing_dhkey_check_pkt"]},
}

fuzz = {
    "fuzz_pcap_filename": "/home/yangting/Documents/Ble_Test/result/log_file/WCH/test_l2cap_fuzz.pcap",
    "untested_layer": ["LL_TERMINATE_IND", "LL_VERSION_IND"],
    "unadd_layer": [] , # 如果有需要，可以在这里添加未添加的层
   #"block_packet":[['ll_terminate_ind_pkt',"BTLE_DATA", "RFU", 0],]
    "block_packet": [],
    "start" : "start",
    "end" : "start",
}