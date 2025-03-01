




# if master sul_type is 0, if slave sul_type is 1
# Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_pkts"} 
from regex import F


device = {
    "advertiser_address": "50:54:7B:C4:D8:3C",
    "sul_type": 0,
    "iat": 1,
    "rat": 0,
    "role": 1,
    "rx_len": 251,
    "tx_len":251,
    "packet_layer":1,
    "config_file": "/home/yangting/Documents/Ble_state_check/srcs/Config_File/WCH/peripheral_07_17_selected.ini",
    "model_path": "/home/yangting/Documents/Ble_state_check/result/dot_file/WCH/pairing_legency_encryption.dot",
    "learned_model_path": "/home/yangting/Documents/Ble_state_check/result/dot_file/WCH/ble_security_l2cap.dot",
    "log_path": "/home/yangting/Documents/Ble_state_check/result/log_file/WCH/test_state.log",
    "port_name": "/dev/ttyACM0",
    "logs_pcap": False,
    "pcap_filename": "/home/yangting/Documents/Ble_state_check/result/log_file/WCH/test_smp_legency.pcap",
    "return_handle_layer": [1,3] ,
    "send_handle_layer":[1,3], # Uncomment and modify if needed
    "key_path": "/home/yangting/Documents/Ble_state_check/result/log_file/WCH/key.txt",
    "statepkt_dict": {"ll_base":['ll_feature_req_pkt','ll_length_req_pkt', 'll_version_ind_pkt',],"sm_legency":['pairing_request_pkt','pairing_confirm_pkt', 'pairing_random_pkt', ],"sm_sc":['pairing_request_pkt','pairing_public_key_pkt',"pairing_random_pkt","pairing_dhkey_check_pkt"]},
}

statecheck = {
    "tested_letters_file" : "/home/yangting/Documents/Ble_state_check/result/log_file/WCH/tested_letters.txt",
    "output_path": "/home/yangting/Documents/Ble_state_check/result/log_file/WCH/output.txt",
    # 参数1 为 上一个的输出，参数2 为后面的输入
    # "block_pattern": [["ll_start_enc_rsp_pkt|ll_start_enc_rsp_pkt,encryption_information_pkt,identity_address_information_pkt,identity_information_pkt,master_identification_pkt,signing_information_pkt","pairing_failed_pkt"],],
    # "block_pattern": [["ll_version_ind_pkt|ll_version_ind_pkt","pairing_request_pkt"]],
}



