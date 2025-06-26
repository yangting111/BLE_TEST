from re import T
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *



#advpkts = ['adv_pkts','adv_ind_pkt','adv_direct_ind_pkt','adv_nonconn_ind','scan_req','scan_rsp','connect_req','adv_scan_ind']
#feature_set ='le_encryption+conn_par_req_proc+ext_reject_ind+slave_init_feat_exch+le_ping+le_data_len_ext+ll_privacy+ext_scan_filter+le_2m_phy+tx_mod_idx+rx_mod_idx+le_coded_phy+le_ext_adv+le_periodic_adv+ch_sel_alg+le_pwr_class'
class BLE_ADV():
    def __init__(self, advertiser_address:str,master_address:str, iat:int, rat:int):
        self.name = "adv_pkts"
        self.iat = iat
        self.rat = rat
        self.advertiser_address = advertiser_address
        self.master_address = master_address

    def ADV_IND_PKT(self):
        pkt = BTLE() / BTLE_ADV()/ BTLE_ADV_IND(AdvA=self.advertiser_address)
        return pkt
    def ADV_DIRECT_IND_PKT(self):
        pkt = BTLE() / BTLE_ADV()/ BTLE_ADV_DIRECT_IND(AdvA=self.advertiser_address)
        return pkt
    def ADV_NONCONN_IND(self):
        pkt = BTLE() / BTLE_ADV()/ BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address)
        return pkt
    def SCAN_REQ(self):
        pkt = BTLE() / BTLE_ADV(RxAdd = self.rat ,TxAdd = self.iat)/ BTLE_SCAN_REQ(ScanA=self.master_address,AdvA=self.advertiser_address)
        return pkt
    def SCAN_RSP(self):
        pkt = BTLE() / BTLE_ADV()/ BTLE_SCAN_RSP(AdvA=self.advertiser_address)
        return pkt
    def CONNECT_REQ(self):
        pkt = BTLE() / BTLE_ADV( RxAdd = self.rat ,TxAdd = self.iat)/ BTLE_CONNECT_REQ(InitA = self.master_address,AdvA=self.advertiser_address,crc_init = 0x179a9c,win_size = 1,\
                                                    win_offset = 0, interval = 16, latency = 0, timeout = 50, chM= 0x1FFFFFFFFF,\
                                                        hop = 5,SCA = 0)
        return pkt
    def ADV_SCAN_IND(self):
        pkt = BTLE() / BTLE_ADV()/ BTLE_ADV_SCAN_IND(AdvA=self.advertiser_address)
        return pkt
    


class BLE_ADV_HANDLE():
    def __init__(self):
        pass

    def receive_adv_handle(self, pkt:Packet) -> Packet:
        return pkt
    def send_adv_handle(self, pkt:Packet):
        return pkt
