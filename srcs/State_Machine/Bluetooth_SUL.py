from cgitb import reset
import logging

from multiprocessing.reduction import send_handle
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../libs/")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../libs/boofuzz/")
from colorama import Fore
import random
from time import sleep
from aalpy.base import SUL
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.all import raw
from Ble_Test.driver.NRF52_dongle import NRF52Dongle
import Ble_Test.srcs.Send_Packet.constant as constant
from Ble_Test.srcs.Send_Packet.Packet_Constuction import Packet_Constuction
from Ble_Test.srcs.Packet_Process.Pcap_Packet_Process import Packet_Process
from Ble_Test.srcs.Fail_Exception.Fail_Exception import *
import configparser






class Bluetooth_SUL(SUL):
    def __init__(self, driver, advertiser_address,iat,rat,role,rx_len,tx_len,logger_handle, key_path=None,packet_layer=None,config_file=None,statepkt_dict=None,return_handle_layer= [],send_handle_layer= []):
        super().__init__()
        self.advertiser_address = advertiser_address
        print("Advertiser Address: ", self.advertiser_address)
 
        self.iat = iat
        self.rat = rat
        self.role = role
        self.slave_addr_type = None
        self.driver = driver
        self.logger_handle = logger_handle
        self.logger = logging.getLogger(logger_handle)
        self.advpkts = ["adv_pkts",'adv_ind_pkt','adv_direct_ind_pkt','adv_nonconn_ind','scan_req','scan_rsp','connect_req','adv_scan_ind']
        self.llpkts = ['ll_pkts','ll_connection_update_ind_pkt', 'll_channel_map_req_pkt', 'll_terminate_ind_pkt', 'll_enc_req_pkt', 'll_enc_rsp_pkt', 'll_start_enc_req_pkt', 'll_start_enc_rsp_pkt', 'll_unknown_rsp_pkt', 'll_feature_req_pkt', 'll_feature_rsp_pkt', 'll_pause_enc_req_pkt', 'll_pause_enc_rsp_pkt', 'll_version_ind_pkt', 'll_reject_ind_pkt', 'll_slave_feature_req_pkt', 'll_connection_param_req_pkt', 'll_connection_param_rsp_pkt', 'll_reject_ind_ext_pkt', 'll_ping_req_pkt', 'll_ping_rsp_pkt', 'll_length_req_pkt', 'll_length_rsp_pkt','ll_empty_pkt']
       

        self.l2cappkts = ["l2cap_pkts",'l2cap_command_reject_rsp_pkt','l2cap_disconnection_req_pkt','l2cap_disconnection_rsp_pkt','l2cap_connection_parameter_update_req_pkt','l2cap_connection_parameter_update_rsp_pkt','l2cap_le_credit_based_connection_req_pkt','l2cap_le_credit_based_connection_rsp_pkt','l2cap_le_flow_control_credit_ind_pkt','l2cap_credit_based_connection_req_pkt','l2cap_credit_based_connection_rsp_pkt','l2cap_credit_based_reconfigure_req_pkt','l2cap_credit_based_reconfigure_rsp_pkt']
        self.smppkts = ['smp_pkts','pairing_request_pkt', 'pairing_response_pkt', 'pairing_confirm_pkt', 'pairing_random_pkt', 'pairing_failed_pkt', 'encryption_information_pkt', 'master_identification_pkt', 'identity_information_pkt', 'identity_address_information_pkt', 'signing_information_pkt', 'security_request_pkt', 'pairing_public_key_pkt', 'pairing_dhkey_check_pkt', 'pairing_keypress_notification_pkt']
        self.attpkts = ["att_pkts","att_error_rsp_pkt","att_exchange_mtu_req_pkt","att_exchange_mtu_rsp_pkt","att_find_information_req_pkt","att_find_information_rsp_pkt","att_find_by_type_value_req_pkt","att_find_by_type_value_rsp_pkt","att_read_by_type_req_pkt","att_read_by_type_rsp_pkt","att_read_req_pkt","att_read_rsp_pkt","att_read_blob_req_pkt","att_read_blob_rsp_pkt","att_read_multiple_req_pkt","att_read_multiple_rsp_pkt","att_read_by_group_type_req_pkt","att_read_by_group_type_rsp_pkt","att_read_multiple_variable_req_pkt","att_read_multiple_variable_rsp_pkt","att_write_req_pkt","att_write_rsp_pkt","att_write_cmd_pkt","att_signed_write_pkt","att_prepare_write_req_pkt","att_prepare_write_rsp_pkt","att_execute_write_req_pkt","att_execute_write_rsp_pkt","att_handle_value_notification_pkt","att_handle_value_indication_pkt","att_handle_value_confirmation_pkt","att_multiple_handle_value_notification_pkt"]


        self.connection_error_counter = 0
        self.packet_layer = packet_layer
        self.config_file = config_file

        self.return_handle_layer = return_handle_layer
        self.send_handle_layer = send_handle_layer
        self.logger.info("Advertiser Address: " + self.advertiser_address)

        self.exit_flag = False
        self.config = configparser.ConfigParser()
        print("config_file: ", config_file) 
        self.config.read(config_file)
        self.print_show = False
        self.rx_len = rx_len
        self.tx_len = tx_len
        self.key_path = key_path
        self.pairing_times = 0
        if statepkt_dict == None:
            statepkt_dict = {}
        else:
            self.statepkt_dict = statepkt_dict
        self.data_prepare()
        self.data_processing()


    def data_prepare(self):
        rand_hex_str = hex(random.getrandbits(48))[2:].zfill(12)
        self.master_address = ':'.join(a+b for a,b in zip(rand_hex_str[::2], rand_hex_str[1::2]))
   
        print("Master Address: ", self.master_address)
        print("Advertiser Address: ", self.advertiser_address)
        self.access_address = int(hex(random.getrandbits(32)),0)
        self.packet_construction = Packet_Constuction(self.access_address,self.advertiser_address,self.master_address,self.iat,self.rat,self.role,self.rx_len,self.tx_len,self.logger_handle,key_path=self.key_path)
        self.packet_process = Packet_Process(access_address=self.access_address)

        self.packet_construction.get_pkts(self.advpkts)
        self.packet_construction.get_pkts(self.llpkts)
        self.packet_construction.get_pkts(self.l2cappkts)
        self.packet_construction.get_pkts(self.smppkts)
        self.packet_construction.get_pkts(self.attpkts)

    def data_processing(self):

        self.packet_construction.set_pkts('adv_pkts',[      ['scan_req','BTLE_SCAN_REQ','ScanA',self.master_address],
                                                            ['connect_req','BTLE_CONNECT_REQ','AdvA',self.advertiser_address],
                                                            ['connect_req','BTLE_CONNECT_REQ','AA',self.access_address.to_bytes(4, byteorder='little')],
                                                            ['connect_req','BTLE_CONNECT_REQ','crc_init',0x179a9c],
                                                            ['connect_req','BTLE_CONNECT_REQ','win_size',2],
                                                            ['connect_req','BTLE_CONNECT_REQ','win_offset',1],
                                                            ['connect_req','BTLE_CONNECT_REQ','interval',16],
                                                            ['connect_req','BTLE_CONNECT_REQ','latency',0],
                                                            ['connect_req','BTLE_CONNECT_REQ','timeout',10],
                                                            ['connect_req','BTLE_CONNECT_REQ','chM',0x1FFFFFFFFF],
                                                            ['connect_req','BTLE_CONNECT_REQ','hop',5],
                                                            ['connect_req','BTLE_CONNECT_REQ','SCA',0],
                                                            ])
        self.packet_construction.set_pkts('ll_pkts',[       ['ll_connection_update_ind_pkt','LL_CONNECTION_UPDATE_IND','win_size',2],
                                                            ['ll_connection_update_ind_pkt','LL_CONNECTION_UPDATE_IND','win_offset',1],
                                                            ['ll_connection_update_ind_pkt','LL_CONNECTION_UPDATE_IND','interval',16],
                                                            ['ll_connection_update_ind_pkt','LL_CONNECTION_UPDATE_IND','latency',0],
                                                            ['ll_connection_update_ind_pkt','LL_CONNECTION_UPDATE_IND','timeout',10],
                                                            ['ll_connection_update_ind_pkt','LL_CONNECTION_UPDATE_IND','instant',0],
                                                            ['ll_channel_map_req_pkt','LL_CHANNEL_MAP_IND','chM',0x1FFFFFFFFF],
                                                            ['ll_terminate_ind_pkt','LL_TERMINATE_IND','code',0],
                                                            ['ll_enc_req_pkt','LL_ENC_REQ','rand',int(hex(random.getrandbits(64)),0)],
                                                            ['ll_enc_req_pkt','LL_ENC_REQ','ediv',int(hex(random.getrandbits(16)),0)],
                                                            ['ll_enc_req_pkt','LL_ENC_REQ','skdm',int(hex(random.getrandbits(64)),0)],
                                                            ['ll_enc_req_pkt','LL_ENC_REQ','ivm',int(hex(random.getrandbits(32)),0)],
                                                            ['ll_enc_rsp_pkt','LL_ENC_RSP','skds',int(hex(random.getrandbits(64)),0)],
                                                            ['ll_enc_rsp_pkt','LL_ENC_RSP','ivs',int(hex(random.getrandbits(32)),0)],
                                                            ['ll_unknown_rsp_pkt','LL_UNKNOWN_RSP','code',int(hex(random.getrandbits(8)),0)],
                                                            ['ll_feature_req_pkt','LL_FEATURE_REQ','feature_set','le_encryption+conn_par_req_proc+ext_reject_ind+slave_init_feat_exch+le_ping+le_data_len_ext+ll_privacy+ext_scan_filter+le_2m_phy+tx_mod_idx+rx_mod_idx+le_coded_phy+le_ext_adv+le_periodic_adv+ch_sel_alg+le_pwr_class'],
                                                            ['ll_feature_rsp_pkt','LL_FEATURE_RSP','feature_set','le_encryption+conn_par_req_proc+ext_reject_ind+slave_init_feat_exch+le_ping+le_data_len_ext+ll_privacy+ext_scan_filter+le_2m_phy+tx_mod_idx+rx_mod_idx+le_coded_phy+le_ext_adv+le_periodic_adv+ch_sel_alg+le_pwr_class'],
                                                            ['ll_pause_enc_req_pkt','LL_PAUSE_ENC_REQ'],
                                                            ['ll_pause_enc_rsp_pkt','LL_PAUSE_ENC_RSP'],
                                                            ['ll_version_ind_pkt','LL_VERSION_IND','version','4.2'],
                                                            ['ll_reject_ind_pkt','LL_REJECT_IND','code',int(hex(random.getrandbits(8)),0)],
                                                            ['ll_slave_feature_req_pkt','LL_SLAVE_FEATURE_REQ','feature_set','le_encryption+conn_par_req_proc+ext_reject_ind+slave_init_feat_exch+le_ping+le_data_len_ext+ll_privacy+ext_scan_filter+le_2m_phy+tx_mod_idx+rx_mod_idx+le_coded_phy+le_ext_adv+le_periodic_adv+ch_sel_alg+le_pwr_class'],
                                                            ['ll_connection_param_req_pkt','LL_CONNECTION_PARAM_REQ','interval_min',0x16],
                                                            ['ll_connection_param_req_pkt','LL_CONNECTION_PARAM_REQ','interval_max',0x20],
                                                            ['ll_connection_param_req_pkt','LL_CONNECTION_PARAM_REQ','latency',0],
                                                            ['ll_connection_param_req_pkt','LL_CONNECTION_PARAM_REQ','timeout',50],
                                                            ['ll_connection_param_rsp_pkt','LL_CONNECTION_PARAM_RSP','interval_min',0x16],
                                                            ['ll_connection_param_rsp_pkt','LL_CONNECTION_PARAM_RSP','interval_max',0x20],
                                                            ['ll_connection_param_rsp_pkt','LL_CONNECTION_PARAM_RSP','latency',0],
                                                            ['ll_connection_param_rsp_pkt','LL_CONNECTION_PARAM_RSP','timeout',50],
                                                            ['ll_reject_ind_ext_pkt','LL_REJECT_EXT_IND','reject_opcode',int(hex(random.getrandbits(8)),0)],
                                                            ['ll_reject_ind_ext_pkt','LL_REJECT_EXT_IND','error_code',int(hex(random.getrandbits(8)),0)],
                                                            ['ll_ping_req_pkt','LL_PING_REQ'],
                                                            ['ll_ping_rsp_pkt','LL_PING_RSP'],
                                                            ['ll_length_req_pkt','LL_LENGTH_REQ','max_rx_bytes',251],
                                                            ['ll_length_req_pkt','LL_LENGTH_REQ','max_tx_bytes',251],
                                                            ['ll_length_rsp_pkt','LL_LENGTH_RSP','max_rx_bytes',251],
                                                            ['ll_length_rsp_pkt','LL_LENGTH_RSP','max_tx_bytes',251],

                                                            ])

    def packet_send_received_control(self, send_pkt, connect_min_attempts=constant.NORMAL_MIN_ATTEMPTS, connect_max_attempts=constant.NORMAL_MAX_ATTEMPTS, repeat=None, log = False): 
        received = []
        result = set()
        return_list = []

        print(Fore.YELLOW + "TX ---> " +"|".join(send_pkt.summary().split(" / ")) )

        packet_back = self.packet_construction.send_packet_handler(send_pkt)
        if packet_back:
            self.logger.debug("packet_send")
            send_pkt = packet_back

        
        if isinstance(send_pkt,list):
            for i, pkt in enumerate(send_pkt):
                if i == len(send_pkt) - 1:
                    received_set = self.packet_send_received(pkt, connect_max_attempts, connect_max_attempts+1, repeat)
                else:
                    received_set = self.packet_send_received(pkt, connect_min_attempts, connect_min_attempts+1, repeat)
                if received_set:
                    received.extend(received_set)

        else:
            send_pkt.show2()
            received = self.packet_send_received(send_pkt, connect_min_attempts, connect_max_attempts, repeat)
        if received:
            for pkt in received:            
                if self.return_handle_layer:

                    re_pkt = self.packet_construction.receive_packet_handler(pkt)
                    if re_pkt!=None:
                        pkt = re_pkt

                        re_pkt.show2()  
                        if re_pkt.haslayer("BTLE_CTRL"):
                           print(raw(re_pkt.getlayer("BTLE_CTRL")).hex())

                
                result.update(pkt.summary().split(" / "))   
                return_list = "|".join(sorted(result))
            print(Fore.YELLOW + "RX <--- " + return_list)
            return return_list if return_list else constant.EMPTY
        else:
            return constant.EMPTY

 
    def packet_send_received(self, send_pkt:Packet, connect_min_attempts=constant.NORMAL_MIN_ATTEMPTS, connect_max_attempts=constant.NORMAL_MAX_ATTEMPTS, repeat=None):
        pkt = None
        attempts = 0
        received_data = []
        check_data = set()
        ####
        
        self.logger.info("TX ---> " + send_pkt.summary())
        

        self.driver.send(send_pkt)
 

        while attempts < connect_min_attempts or (not self.driver.contains_more_data(check_data) and attempts < connect_max_attempts):


            attempts = attempts + 1

            data = self.driver.raw_receive()

            if data:

                pkt = BTLE(data)
                if pkt is not None:

                    if 'BTLE_DATA' in pkt and pkt.getlayer('BTLE_DATA').len > 0:

   
                        summary = pkt.summary()
                        check_data.update(summary.split(" / "))

                        print(Fore.MAGENTA + "RX <--- " + summary)


                        received_data.append(pkt)

                    elif send_pkt.haslayer('BTLE_SCAN_REQ') and ('BTLE_SCAN_RSP' in pkt) and hasattr(pkt, 'AdvA') and self.advertiser_address.upper() == pkt.AdvA.upper():
                        self.slave_addr_type = pkt.TxAdd
                        summary = pkt.summary()
                        check_data.update(summary.split(" / "))
                        print(Fore.MAGENTA + "RX <--- " + summary)
                        received_data.append(pkt)


        
        return received_data
    def connection_packet_send_received(self, send_pkt:Packet, connect_min_attempts=constant.CONNECT_MIN_ATTEMPTS, connect_max_attempts=constant.CONNECT_MAX_ATTEMPTS, repeat=None):
        pkt = None
        attempts = 0
        received_data = set()

        self.driver.send(send_pkt)

        while attempts < connect_min_attempts or (not self.driver.wait_for_connection(received_data) and attempts < connect_max_attempts):
            attempts = attempts + 1
            data = self.driver.raw_receive()
            if data:
                pkt = BTLE(data)
                if pkt is not None:
                    if 'BTLE_DATA' in pkt and pkt.getlayer('BTLE_DATA').len > 0:
                        if attempts == connect_max_attempts and ("SM_Hdr" in received_data and 'LL_LENGTH_REQ' not in received_data):
                            connect_max_attempts=+1
                        summary = pkt.summary()
                        print(Fore.MAGENTA + "RX <--- " + summary)
                        received_data.update(summary.split(" / "))

        return received_data if received_data else constant.EMPTY

        
    def pre(self):

        print("-----------------Pre Start-----------------")
        self.data_prepare()
        self.data_processing()
        self.print_show = False
        self.packet_construction.set_encryption(False)
        error_count = 0
        reset_count = 0
        
        if self.role == 1:
            self.packet_send_received(self.packet_construction.get_pkt('scan_req'), connect_min_attempts=constant.SCAN_MIN_ATTEMPTS, connect_max_attempts=constant.SCAN_MAX_ATTEMPTS)
            
            output = self.connection_packet_send_received(self.packet_construction.get_pkt('connect_req'), connect_min_attempts=5, connect_max_attempts=20)
           
            while output == constant.EMPTY:
                error_count += 1
                if error_count < constant.CONNECTION_ERROR_ATTEMPTS:
                    self.driver.send(self.packet_construction.get_pkt('ll_terminate_ind_pkt'))
                    self.packet_send_received(self.packet_construction.get_pkt('scan_req'), connect_min_attempts=constant.SCAN_MIN_ATTEMPTS, connect_max_attempts=constant.SCAN_MAX_ATTEMPTS)
                    output = self.connection_packet_send_received(self.packet_construction.get_pkt('connect_req'), connect_min_attempts=5, connect_max_attempts=20)
                    
                else:
                    print("Error: The device is not ready. Please reset the device")
                    self.driver.reset()
                    reset_count = reset_count + 1
                    error_count = 0
                    if reset_count > 2:
                        sleep(100)
                        if reset_count > 4:
                            raise ConnectionError()

        if self.packet_layer == 'll_pkts':
            pass
        elif self.packet_layer == 'adv_pkts':
           self.packet_send_received(self.packet_construction.get_pkt('scan_req'), connect_min_attempts=constant.SCAN_MIN_ATTEMPTS, connect_max_attempts=constant.SCAN_MAX_ATTEMPTS)

        elif self.packet_layer == 'att_pkts':

            pkt_list = self.packet_process.read_pre_packet(self.config_file,self.config.items(self.packet_layer)[0][0].split("_")[0])
            for value in pkt_list:
                timestamp, pkt = value
                self.packet_send_received(pkt, connect_min_attempts=constant.NORMAL_MIN_ATTEMPTS, connect_max_attempts=constant.NORMAL_MAX_ATTEMPTS)
        elif self.packet_layer == 'smp_pkts':

            pkt_list = self.packet_process.read_pre_packet(self.config_file,self.config.items(self.packet_layer)[0][0].split("_")[0])
            
            for value in pkt_list:
                timestamp, pkt = value
                self.packet_send_received(pkt, connect_min_attempts=constant.NORMAL_MIN_ATTEMPTS, connect_max_attempts=constant.NORMAL_MAX_ATTEMPTS)
        elif self.packet_layer == 'l2cap_pkts':

            pkt_list = self.packet_process.read_pre_packet(self.config_file,self.config.items("smp_pkts")[0][0].split("_")[0])
            for value in pkt_list:
                timestamp, pkt = value 
                self.packet_send_received(pkt, connect_min_attempts=constant.NORMAL_MIN_ATTEMPTS, connect_max_attempts=constant.NORMAL_MAX_ATTEMPTS)

        elif self.packet_layer == 'test_legency_pkts':
            pkt_list = self.packet_process.read_pre_packet(self.config_file,self.config.items("att_pkts")[0][0].split("_")[0])
       
            for value in pkt_list:
                timestamp, pkt = value
                self.packet_send_received(pkt, connect_min_attempts=constant.NORMAL_MIN_ATTEMPTS, connect_max_attempts=constant.NORMAL_MAX_ATTEMPTS)
            pkt = self.get_packet("pairing_request_pkt")
            pkt["SM_Pairing_Request"].iocap = 0x03
            pkt["SM_Pairing_Request"].oob = 0x00
            pkt["SM_Pairing_Request"].authentication = 0x2d
            pkt["SM_Pairing_Request"].max_key_size = 0x10
            pkt["SM_Pairing_Request"].initiator_key_distribution = 0x0f
            pkt["SM_Pairing_Request"].responder_key_distribution = 0x0f

            self.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 20,connect_max_attempts = 150)

            pkt = self.get_packet("pairing_confirm_pkt")
            self.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 20,connect_max_attempts = 150)
            pkt = self.get_packet("pairing_random_pkt")
          
            self.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 20,connect_max_attempts = 100)   

        elif self.packet_layer == 'test_sc_pkts':
            pkt_list = self.packet_process.read_pre_packet(self.config_file,self.config.items("att_pkts")[0][0].split("_")[0])
           
            for value in pkt_list:
                timestamp, pkt = value
                self.packet_send_received(pkt, connect_min_attempts=constant.NORMAL_MIN_ATTEMPTS, connect_max_attempts=constant.NORMAL_MAX_ATTEMPTS)
            pkt = self.get_packet("pairing_request_pkt")
            pkt["SM_Pairing_Request"].iocap = 0x03
            pkt["SM_Pairing_Request"].oob = 0x00
            pkt["SM_Pairing_Request"].authentication = 0x2d
            pkt["SM_Pairing_Request"].max_key_size = 0x10
            pkt["SM_Pairing_Request"].initiator_key_distribution = 0x0f
            pkt["SM_Pairing_Request"].responder_key_distribution = 0x0f
        
            self.packet_send_received_control(send_pkt=pkt)
            pkt = self.get_packet("pairing_public_key_pkt")
            
            self.packet_send_received_control(send_pkt=pkt)

            pkt = self.get_packet("pairing_random_pkt")
            
            self.packet_send_received_control(send_pkt=pkt)   
            pkt = self.get_packet("pairing_dhkey_check_pkt")
            
            self.packet_send_received_control(send_pkt=pkt)
        elif self.packet_layer == "test_all_pkts":
            # pkt = self.get_packet("ll_length_req_pkt")
            # self.packet_send_received_control(send_pkt=pkt,connect_min_attempts = 20,connect_max_attempts = 100)
            pass

            

            


        else:
            pass

        print("-----------------Pre End-----------------")


    def post(self):
        print("-----------------Post Start-----------------")
        for i in range(3):
            terminate_pkt = self.packet_construction.get_pkt('ll_terminate_ind_pkt')
            self.driver.send(terminate_pkt)
        sleep(1)
           
            
        print("-----------------Post End-----------------")

    def step(self, input_symbol, log = False):

        if input_symbol in self.statepkt_dict:
            pkt_list = self.statepkt_dict[input_symbol]
            input_symbol = pkt_list
        

        if isinstance(input_symbol, list):
            
            received_data = set()
            
            for send_packet in input_symbol:
                

                section = self.packet_construction.find_section(send_packet)

                pkt_dict = self.packet_process.read_config_packet(self.config_file,section)
                if isinstance(send_packet, Packet):
                    pkt = send_packet
                elif isinstance(send_packet, str):
                    pkt = self.packet_construction.get_pkt(send_packet,pkt_dict)
                
                
                output = self.packet_send_received_control(pkt,log=True)
                if output == constant.EMPTY:
                    continue
                received_data.add(tuple(output.split("|")))


            return "|".join(str(item) for item in sorted(received_data)) if len(received_data) != 0 else None

        elif isinstance(input_symbol, str):
            

            section = self.packet_construction.find_section(input_symbol)


            pkt_dict = self.packet_process.read_config_packet(self.config_file,section)

            pkt = self.packet_construction.get_pkt(input_symbol,pkt_dict)

            received_data = self.packet_send_received_control(pkt,log=True)
            return received_data
        elif isinstance(input_symbol, Packet):
            received_data = self.packet_send_received_control(input_symbol,log=True)
            return received_data
        
        else:

            return constant.ERROR
                
    def query(self, word):
 
        self.performed_steps_in_query = 0
        out = constant.ERROR
        error_counter = 0
        while out == constant.ERROR and error_counter < constant.CONNECTION_ERROR_ATTEMPTS:
            self.pre()
            outputs = []
            num_steps = 0
            for letter in word:
                out = self.step(letter)
                num_steps += 1
                if out == constant.ERROR:
                    print(Fore.RED + "ERROR reported")
                    self.connection_error_counter += 1
                    self.post()
                    self.num_queries += 1
                    self.performed_steps_in_query += num_steps
                    self.num_steps += num_steps
                    break

                outputs.append(out)
            if out == constant.ERROR:
                error_counter += 1
                continue
            self.post()
            self.num_queries += 1
            self.performed_steps_in_query += len(word)
            self.num_steps += len(word)
            return outputs
        raise ConnectionError()
    
    
    def reset(self):

        pass

    def handle_sigtstp(self, signum, frame):
        print("Caught SIGTSTP (Ctrl+Z)")
        # save_log
        # exit_query
        self.exit_flag = True
        print("learning exit")
        self.logger.info("learning exit")

    def get_packet(self, pkt_name:str):

        section = self.packet_construction.find_section(pkt_name)

        pkt_dict = self.packet_process.read_config_packet( self.config_file, section)

        pkt = self.packet_construction.get_pkt(pkt_name,pkt_dict)

        return pkt


    




