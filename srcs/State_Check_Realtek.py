from calendar import c
import sys
import os
import resource
from tracemalloc import start
import time
import random

from numpy import block

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/libs/")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/libs/boofuzz/")
from aalpy.utils import load_automaton_from_file
from Ble_state_check.srcs.State_Machine.WMethodEqOracle import WMethodEqOracle
from Ble_state_check.srcs.State_Machine.Bluetooth_SUL import Bluetooth_SUL
from Ble_state_check.driver.NRF52_dongle import NRF52Dongle
from Fail_Exception.FailSafeCacheSUL import FailSafeCacheSUL
from Fail_Exception.Fail_Exception import *
from Ble_state_check.srcs.Log_Config.logger_config import *
from Ble_state_check.srcs.Config_File.Realtek import config

rsrc = resource.RLIMIT_DATA
soft, hard = resource.getrlimit(rsrc)
resource.setrlimit(rsrc, (1024 * 1024 * 1024 * 12, hard))

Layers = {0:"adv_pkts", 1:"ll_pkts", 2:"l2cap_pkts", 3:"smp_pkts", 4:"att_pkts",5:"test_legency_pkts",6:"test_sc_pkts"}

# sul config
advertiser_address = config.device["advertiser_address"]
iat = config.device["iat"]
rat = config.device["rat"]
role = config.device["role"]
rx_len = config.device["rx_len"]
tx_len = config.device["tx_len"]
test_layer = Layers[config.device["packet_layer"]]
config_file = config.device["config_file"]
logger_handle = config_file.split('/')[-1].split('.')[0]

logger = configure_logger( logger_handle, config.device["log_path"],logging.DEBUG)

model_path = config.device["model_path"]
return_handle_layer = [Layers[i] for i in config.device["return_handle_layer"]]
send_handle_layer = [Layers[i] for i in config.device["send_handle_layer"]]
port_name = config.device["port_name"]
logs_pcap = config.device["logs_pcap"]
pcap_filename = config.device["pcap_filename"]
key_path = config.device["key_path"]
tested_letters_file = config.statecheck["tested_letters_file"]
out_put_path = config.statecheck["output_path"]
block_pattern = config.statecheck["block_pattern"]

def callback(seq,input_output):
    for pattern in block_pattern:
        if (pattern[0] in input_output[-1]):
            if pattern[1] in seq:
                return True
    return False


ble_sul = Bluetooth_SUL(NRF52Dongle(port_name=port_name,logs_pcap=logs_pcap,pcap_filename=pcap_filename), advertiser_address,iat,rat, role,rx_len,tx_len ,logger_handle, key_path,test_layer, config_file, return_handle_layer=return_handle_layer,send_handle_layer=send_handle_layer)

# sul = FailSafeCacheSUL(ble_sul)
# all packet
advpkts = ['adv_ind_pkt','adv_direct_ind_pkt','adv_nonconn_ind','scan_req','scan_rsp','connect_req','adv_scan_ind']
llpkts = ['ll_connection_update_ind_pkt', 'll_channel_map_req_pkt', 'll_terminate_ind_pkt', 'll_enc_req_pkt', 'll_enc_rsp_pkt', 'll_start_enc_req_pkt', 'll_start_enc_rsp_pkt', 'll_unknown_rsp_pkt', 'll_feature_req_pkt', 'll_feature_rsp_pkt', 'll_pause_enc_req_pkt', 'll_pause_enc_rsp_pkt', 'll_version_ind_pkt', 'll_reject_ind_pkt', 'll_slave_feature_req_pkt', 'll_connection_param_req_pkt', 'll_connection_param_rsp_pkt', 'll_reject_ind_ext_pkt', 'll_ping_req_pkt', 'll_ping_rsp_pkt', 'll_length_req_pkt', 'll_length_rsp_pkt']
l2cappkts = ['l2cap_command_reject_rsp_pkt','l2cap_disconnection_req_pkt','l2cap_disconnection_rsp_pkt','l2cap_connection_parameter_update_req_pkt','l2cap_connection_parameter_update_rsp_pkt','l2cap_le_credit_based_connection_req_pkt','l2cap_le_credit_based_connection_rsp_pkt','l2cap_le_flow_control_credit_ind_pkt','l2cap_credit_based_connection_req_pkt','l2cap_credit_based_connection_rsp_pkt','l2cap_credit_based_reconfigure_req_pkt','l2cap_credit_based_reconfigure_rsp_pkt']
smppkts = ['pairing_request_pkt', 'pairing_response_pkt', 'pairing_confirm_pkt', 'pairing_random_pkt', 'pairing_failed_pkt', 'encryption_information_pkt', 'master_identification_pkt', 'identity_information_pkt', 'identity_address_information_pkt', 'signing_information_pkt', 'security_request_pkt', 'pairing_public_key_pkt', 'pairing_dhkey_check_pkt', 'pairing_keypress_notification_pkt']
attpkts = ["att_error_rsp_pkt","att_exchange_mtu_req_pkt","att_exchange_mtu_rsp_pkt","att_find_information_req_pkt","att_find_information_rsp_pkt","att_find_by_type_value_req_pkt","att_find_by_type_value_rsp_pkt","att_read_by_type_req_pkt","att_read_by_type_rsp_pkt","att_read_req_pkt","att_read_rsp_pkt","att_read_blob_req_pkt","att_read_blob_rsp_pkt","att_read_multiple_req_pkt","att_read_multiple_rsp_pkt","att_read_by_group_type_req_pkt","att_read_by_group_type_rsp_pkt","att_read_multiple_variable_req_pkt","att_read_multiple_variable_rsp_pkt","att_write_req_pkt","att_write_rsp_pkt","att_write_cmd_pkt","att_signed_write_pkt","att_prepare_write_req_pkt","att_prepare_write_rsp_pkt","att_execute_write_req_pkt","att_execute_write_rsp_pkt","att_handle_value_notification_pkt","att_handle_value_indication_pkt","att_handle_value_confirmation_pkt","att_multiple_handle_value_notification_pkt"]

# alphabet
alphabet = []
alphabet.extend(llpkts)
alphabet.extend(smppkts)
alphabet.append('connect_req')
elements_to_remove = ['ll_connection_update_ind_pkt', 'll_channel_map_req_pkt', 'll_terminate_ind_pkt','ll_connection_param_req_pkt']

for element in elements_to_remove:
    if element in alphabet:
        alphabet.remove(element)

random.shuffle(alphabet)
# Load the automaton from the file
automaton = load_automaton_from_file(model_path,
                                     automaton_type ='mealy',compute_prefixes = True)
automaton.make_input_complete()

# Create the WMethodEqOracle object
w_method_eq_oracle = WMethodEqOracle(alphabet= alphabet, sul = ble_sul, max_number_of_states = 10, shuffle_test_set = True, tested_letters_file = tested_letters_file, out_put_path = out_put_path,callback=callback)
start_time = time.time()
w_method_eq_oracle.find_cex(automaton)
print("Time: ", time.time() - start_time)




    


                                     







