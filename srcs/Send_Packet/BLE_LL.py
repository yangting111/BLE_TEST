
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from Ble_Test.libs.ble_decrypter.utils.ll_enc import *



#llpkts = ['ll_pkts','ll_connection_update_ind_pkt', 'll_channel_map_req_pkt', 'll_terminate_ind_pkt', 'll_enc_req_pkt', 'll_enc_rsp_pkt', 'll_start_enc_req_pkt', 'll_start_enc_rsp_pkt', 'll_unknown_rsp_pkt', 'll_feature_req_pkt', 'll_feature_rsp_pkt', 'll_pause_enc_req_pkt', 'll_pause_enc_rsp_pkt', 'll_version_ind_pkt', 'll_reject_ind_pkt', 'll_slave_feature_req_pkt', 'll_connection_param_req_pkt', 'll_connection_param_rsp_pkt', 'll_reject_ind_ext_pkt', 'll_ping_req_pkt', 'll_ping_rsp_pkt', 'll_length_req_pkt', 'll_length_rsp_pkt','ll_empty']
#feature_set ='le_encryption+conn_par_req_proc+ext_reject_ind+slave_init_feat_exch+le_ping+le_data_len_ext+ll_privacy+ext_scan_filter+le_2m_phy+tx_mod_idx+rx_mod_idx+le_coded_phy+le_ext_adv+le_periodic_adv+ch_sel_alg+le_pwr_class'
class BLE_LL():
    def __init__(self, access_address):
        self.name = "ll_pkts"
        self.access_address = access_address

    def LL_CONNECTION_UPDATE_IND_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_CONNECTION_UPDATE_IND()
        return pkt
    def LL_CHANNEL_MAP_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_CHANNEL_MAP_IND()
        return pkt
    def LL_TERMINATE_IND_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_TERMINATE_IND()
        return pkt
    def LL_ENC_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_ENC_REQ()
        return pkt
    def LL_ENC_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_ENC_RSP()
        return pkt
    def LL_START_ENC_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_START_ENC_REQ()
        return pkt
    def LL_START_ENC_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_START_ENC_RSP()
        return pkt
    def LL_UNKNOWN_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_UNKNOWN_RSP()
        return pkt
    def LL_FEATURE_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_FEATURE_REQ()
        return pkt
    def LL_FEATURE_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_FEATURE_RSP()
        return pkt
    def LL_PAUSE_ENC_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_PAUSE_ENC_REQ()
        return pkt
    def LL_PAUSE_ENC_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_PAUSE_ENC_RSP()
        return pkt
    def LL_VERSION_IND_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_VERSION_IND()
        return pkt
    def LL_REJECT_IND_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_REJECT_IND()
        return pkt
    def LL_SLAVE_FEATURE_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_SLAVE_FEATURE_REQ()
        return pkt
    def LL_CONNECTION_PARAM_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_CONNECTION_PARAM_REQ()
        return pkt
    def LL_CONNECTION_PARAM_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_CONNECTION_PARAM_RSP()
        return pkt
    def LL_REJECT_IND_EXT_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_REJECT_EXT_IND()
        return pkt
    def LL_PING_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_PING_REQ()
        return pkt
    def LL_PING_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_PING_RSP()
        return pkt
    def LL_LENGTH_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_LENGTH_REQ()
        return pkt
    def LL_LENGTH_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / LL_LENGTH_RSP()
        return pkt
    def LL_EMPTY_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() 
        return pkt
    

class BLE_LL_HANDLE():
    def __init__(self,ll_enc:LL_ENC):
        self.ll_enc = ll_enc
    def receive_ll_handle(self, pkt:Packet, decrpted:bool = False):
        result = self.ll_enc.ll_command(pkt, decrpted)

        if result is not None:

            return result
        


    def send_ll_handle(self, pkt:Packet):
 
        result = self.ll_enc.get_packet(pkt)
        if result is not None:
            return result
        else:
            return pkt
        

    # def ll_fragment(self,pkt,fragsize = 27) -> List[Packet]:
    #     p = pkt
    #     lst =[]
    #     total_len = len(raw(p))
    #     nb = total_len//fragsize + 1
    #     for i in range(nb):
    #         if i == 0:
    #             f = BTLE(access_addr=self.access_address) / BTLE_DATA(LLID = 0x02,SN = 1,NESN = 1, MD = 1)/raw(p)[0:(fragsize)]
    #         elif i == nb-1:
    #             f = BTLE(access_addr=self.access_address) / BTLE_DATA(LLID = 0x01,SN = 1,NESN = 1) / raw(p)[fragsize+(i-1)*(fragsize):]
    #         else:
    #             f = BTLE(access_addr=self.access_address) / BTLE_DATA(LLID = 0x01,SN = 0,NESN = 0, MD =1)/raw(p)[(i)*(fragsize):(i+1)*(fragsize)]
    #         lst.append(f)
    #     return lst