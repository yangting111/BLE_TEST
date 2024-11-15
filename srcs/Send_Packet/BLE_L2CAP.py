from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.packet import *


#l2cap_pkts = ["l2cap_pkts",'l2cap_command_reject_rsp_pkt','l2cap_connection_req_pkt','l2cap_connection_rsp_pkt','l2cap_configuration_req_pkt','l2cap_configuration_rsp_pkt','l2cap_disconnection_req_pkt','l2cap_disconnection_rsp_pkt','l2cap_echo_req_pkt','l2cap_echo_rsp_pkt','l2cap_information_req_pkt','l2cap_information_rsp_pkt','l2cap_create_channel_req_pkt','l2cap_create_channel_rsp_pkt','l2cap_move_channel_req_pkt','l2cap_move_channel_rsp_pkt','l2cap_move_channel_confirmation_req_pkt','l2cap_move_channel_confirmation_rsp_pkt','l2cap_connection_parameter_update_req_pkt','l2cap_connection_parameter_update_rsp_pkt','l2cap_le_credit_based_connection_req_pkt','l2cap_le_credit_based_connection_rsp_pkt','l2cap_le_flow_control_credit_ind_pkt','l2cap_credit_based_connection_req_pkt','l2cap_credit_based_connection_rsp_pkt','l2cap_credit_based_reconfigure_req_pkt','l2cap_credit_based_reconfigure_rsp_pkt']
class BLE_L2CAP():
    def __init__(self, access_address):
        self.name = "l2cap_pkts"
        self.access_address = access_address

    def L2CAP_COMMAND_REJECT_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_CmdRej())
        return pkt
    # def L2CAP_CONNECTION_REQ_PKT(self):
    #     pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_ConnReq())
    #     return pkt
    # def L2CAP_CONNECTION_RSP_PKT(self):
    #     pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_ConnResp())
    #     return pkt
    # def L2CAP_CONFIGURATION_REQ_PKT(self):
    #     pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_ConfReq())
    #     return pkt
    # def L2CAP_CONFIGURATION_RSP_PKT(self):
    #     pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_ConfResp())
        return pkt
    def L2CAP_DISCONNECTION_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_DisconnReq())
        return pkt
    def L2CAP_DISCONNECTION_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_DisconnResp())
        return pkt
    # def L2CAP_ECHO_REQ_PKT(self):
    #     pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr())/ L2CAP_EchoReq()
    #     return pkt
    # def L2CAP_ECHO_RSP_PKT(self):
    #     pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr())/ L2CAP_EchoResp()
    #     return pkt
    # def L2CAP_INFORMATION_REQ_PKT(self):
    #     pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_InfoReq())
    #     return pkt
    # def L2CAP_INFORMATION_RSP_PKT(self):
    #     pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_InfoResp())
    #     return pkt
    # def L2CAP_CREATE_CHANNEL_REQ_PKT(self):
    #     pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_Create_Channel_Request())
    #     return pkt
    # def L2CAP_CREATE_CHANNEL_RSP_PKT(self):
    #     pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_Create_Channel_Response())
    #     return pkt
    # def L2CAP_MOVE_CHANNEL_REQ_PKT(self):
    #     pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_Move_Channel_Request())
    #     return pkt
    # def L2CAP_MOVE_CHANNEL_RSP_PKT(self):
    #     pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_Move_Channel_Response())
    #     return pkt
    # def L2CAP_MOVE_CHANNEL_CONFIRMATION_REQ_PKT(self):
    #     pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_Move_Channel_Confirmation_Request())
    #     return pkt
    # def L2CAP_MOVE_CHANNEL_CONFIRMATION_RSP_PKT(self):
    #     pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_Move_Channel_Confirmation_Response())
    #     return pkt
    def L2CAP_CONNECTION_PARAMETER_UPDATE_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_Connection_Parameter_Update_Request())
        return pkt
    def L2CAP_CONNECTION_PARAMETER_UPDATE_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_Connection_Parameter_Update_Response())
        return pkt
    def L2CAP_LE_CREDIT_BASED_CONNECTION_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_LE_Credit_Based_Connection_Request())
        return pkt
    def L2CAP_LE_CREDIT_BASED_CONNECTION_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_LE_Credit_Based_Connection_Response())
        return pkt
    def L2CAP_LE_FLOW_CONTROL_CREDIT_IND_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_LE_Flow_Control_Credit_IND())
        return pkt
    def L2CAP_CREDIT_BASED_CONNECTION_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_Credit_Based_Connection_Request())
        return pkt
    def L2CAP_CREDIT_BASED_CONNECTION_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_Credit_Based_Connection_Response())
        return pkt
    def L2CAP_CREDIT_BASED_RECONFIGURE_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_Credit_Based_Reconfigure_Request())
        return pkt
    def L2CAP_CREDIT_BASED_RECONFIGURE_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ fuzz(L2CAP_CmdHdr()/ L2CAP_Credit_Based_Reconfigure_Response())
        return pkt

class BLE_L2CAP_HANDLE():
    def __init__(self):
        pass

    def receive_l2cap_handle(self, pkt:Packet):
        pass
    def send_l2cap_handle(self, pkt:Packet):
        pass