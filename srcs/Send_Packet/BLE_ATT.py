from calendar import c
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from Ble_Test.libs.blesuite.pybt.att import *
from Ble_Test.libs.blesuite.pybt.gatt import *
from Ble_Test.libs.blesuite.pybt.sm import *
# from Ble_Test.libs.blesuite.gatt_procedures_copy import *
Error_Response = 0x01
Exchange_MTU_Request = 0x02  
Exchange_MTU_Response = 0x03 
Find_Information_Request  = 0x04
Find_Information_Response  = 0x05
Find_By_Type_Value_Request  = 0x06
Find_By_Type_Value_Response  = 0x07
Read_By_Type_Request  = 0x08
Read_By_Type_Response  = 0x09
Read_Request  = 0x0a
Read_Response  = 0x0b
Read_Blob_Request  = 0x0c
Read_Blob_Response  = 0x0d
Read_Multiple_Request  = 0x0e
Read_Multiple_Response  = 0x0f
Read_By_Group_Type_Request  = 0x10
Read_By_Group_Type_Response  = 0x11
Write_Request  = 0x12
Write_Response  = 0x13
Write_Command  = 0x52
Prepare_Write_Request = 0x16  
Prepare_Write_Response  = 0x17
Execute_Write_Request  = 0x18
Execute_Write_Response  = 0x19
Multiple_Variable_Request  = 0x20
Multiple_Variable_Response  = 0x21
Handle_Value_Notification  = 0x1b
Handle_Value_Indication  = 0x1d
Handle_Value_Confirmation  = 0x1e
Multiple_Handle_Value_Notification = 0x23  
Signed_Write_Command = 0xd2



#att_pkts = ['att_pkts',"att_error_rsp_pkt","att_exchange_mtu_req_pkt","att_exchange_mtu_rsp_pkt","att_find_infomation_req_pkt","att_find_infomation_rsp_pkt","att_find_by_type_value_req_pkt","att_find_by_type_value_rsp_pkt","att_read_by_type_req_pkt","att_read_by_type_rsp_pkt","att_read_req_pkt","att_read_rsp_pkt","att_read_blob_req_pkt","att_read_blob_rsp_pkt","att_read_multiple_req_pkt","att_read_multiple_rsp_pkt","att_read_by_group_type_req_pkt","att_read_by_group_type_rsp_pkt","att_read_multiple_variable_req_pkt","att_read_multiple_variable_rsp_pkt","att_write_req_pkt","att_write_rsp_pkt","att_write_cmd_pkt","att_signed_write_pkt","att_prepare_write_req_pkt","att_prepare_write_rsp_pkt","att_execute_write_req_pkt","att_execute_write_rsp_pkt","att_handle_value_notification_pkt","att_handle_value_indication_pkt","att_handle_value_confirmation_pkt","att_multiple_handle_value_notification_pkt"]

class BLE_ATT():
    def __init__(self , access_address):
        self.name = "att_pkts"
        self.access_address = access_address
    def ATT_ERROR_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Error_Response()
        return pkt
    def ATT_EXCHANGE_MTU_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu = 23)
        return pkt
    def ATT_EXCHANGE_MTU_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Response(mtu = 23)
        return pkt
    def ATT_FIND_INFORMATION_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Find_Information_Request()
        return pkt
    def ATT_FIND_INFORMATION_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Find_Information_Response()
        return pkt
    def ATT_FIND_BY_TYPE_VALUE_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Find_By_Type_Value_Request()
        return pkt
    def ATT_FIND_BY_TYPE_VALUE_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Find_By_Type_Value_Response()
        return pkt
    def ATT_READ_BY_TYPE_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_By_Type_Request()
        return pkt
    def ATT_READ_BY_TYPE_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_By_Type_Response()
        return pkt
    def ATT_READ_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_Request()
        return pkt
    def ATT_READ_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_Response()
        return pkt
    def ATT_READ_BLOB_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_Blob_Request()
        return pkt
    def ATT_READ_BLOB_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_Blob_Response()
        return pkt
    def ATT_READ_MULTIPLE_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_Multiple_Request()
        return pkt
    def ATT_READ_MULTIPLE_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_Multiple_Response()
        return pkt
    def ATT_READ_BY_GROUP_TYPE_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_By_Group_Type_Request()
        return pkt
    def ATT_READ_BY_GROUP_TYPE_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_By_Group_Type_Response()
        return pkt
    def ATT_READ_MULTIPLE_VARIABLE_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_Multiple_Variable_Request()
        return pkt
    def ATT_READ_MULTIPLE_VARIABLE_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Read_Multiple_Variable_Response()
        return pkt
    def ATT_WRITE_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Write_Request()
        return pkt
    def ATT_WRITE_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Write_Response()
        return pkt
    def ATT_WRITE_CMD_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Write_Command()
        return pkt
    def ATT_SIGNED_WRITE_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Signed_Write_Command()
        return pkt
    def ATT_PREPARE_WRITE_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Prepare_Write_Request()
        return pkt
    def ATT_PREPARE_WRITE_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Prepare_Write_Response()
        return pkt
    def ATT_EXECUTE_WRITE_REQ_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Execute_Write_Request()
        return pkt
    def ATT_EXECUTE_WRITE_RSP_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Execute_Write_Response()
        return pkt
    def ATT_HANDLE_VALUE_NOTIFICATION_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Handle_Value_Notification()
        return pkt
    def ATT_HANDLE_VALUE_INDICATION_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Handle_Value_Indication()
        return pkt
    def ATT_HANDLE_VALUE_CONFIRMATION_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Handle_Value_Confirmation()
        return pkt
    def ATT_MULTIPLE_HANDLE_VALUE_NOTIFICATION_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Multiple_Handle_Value_Notification()
        return pkt
    
class BLE_ATT_HANDLE():
    def __init__(self, access_address, advertiser_address, sm, connection_handle=None):
        self.access_address = access_address
        self.advertiser_address = advertiser_address
        self.connection_handle = connection_handle
        self.client_rx_mtu = 0
        self.server_rx_mtu = 0
        self.attribute_list = []
        self.gatt_server = Server()
        self.sm = sm


        # ATT Packet
        self.error_response = None
        self.exchange_mtu_request =  None
        self.exchange_mtu_response =  None
        self.find_information_request  =  None
        self.find_information_response  =  None
        self.find_by_type_value_request  =  None
        self.find_by_type_value_response  =  None
        self.read_by_type_request  =  None
        self.read_by_type_response  =  None
        self.read_request  =  None
        self.read_response  =  None
        self.read_blob_request  =  None
        self.read_blob_response  =  None
        self.read_multiple_request  =  None
        self.read_multiple_response  =  None
        self.read_by_group_type_request  =  None
        self.read_by_group_type_response  =  None
        self.write_request  =  None
        self.write_response  =  None
        self.write_command  =  None
        self.prepare_write_request =  None 
        self.prepare_write_response  =  None
        self.execute_write_request  =  None
        self.execute_write_response  =  None
        self.multiple_variable_request  =  None
        self.multiple_variable_response  =  None
        self.handle_value_notification  =  None
        self.handle_value_indication  =  None
        self.handle_value_confirmation  =  None
        self.multiple_handle_value_notification =  None 
        self.signed_write_command =  None



    def receive_att_handle(self, pkt:Packet):

        # Response packet handle
        if pkt.getlayer('ATT_Hdr').opcode == Error_Response:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Exchange_MTU_Response:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Find_Information_Response:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Find_By_Type_Value_Response:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Read_By_Type_Response:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Read_By_Type_Request:
            pass

            


        elif pkt.getlayer('ATT_Hdr').opcode == Read_Response:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Read_Blob_Response:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Read_Multiple_Response:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Read_By_Group_Type_Response:        
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Write_Response:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Prepare_Write_Response:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Execute_Write_Response:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Multiple_Variable_Response:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Handle_Value_Indication:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Handle_Value_Confirmation:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Multiple_Handle_Value_Notification:
            pass
        else:
            pass



        # Request packet handle
        if pkt.getlayer('ATT_Hdr').opcode == Exchange_MTU_Request:
            self.exchange_mtu_response = ATT_Hdr() / ATT_Exchange_MTU_Response()
        elif pkt.getlayer('ATT_Hdr').opcode == Find_Information_Request:
            success, body = self.gatt_server.find_information(pkt.start, pkt.end)
            if success:
                self.find_information_response = ATT_Hdr() / ATT_Find_Information_Response(body)
            else:
                self.error_response = ATT_Hdr() / ATT_Error_Response(request=pkt.getlayer('ATT_Hdr').opcode, handle=pkt.start, ecode=body)
        elif pkt.getlayer('ATT_Hdr').opcode == Find_By_Type_Value_Request:
            success, body = self.gatt_server.find_by_type_value(pkt.start, pkt.end, pkt.uuid, pkt.data)
            if success:
                self.find_by_type_value_response =  ATT_Hdr() / ATT_Find_By_Type_Value_Response(body)
            else:
                self.error_response =  ATT_Error_Response(request=pkt.getlayer('ATT_Hdr').opcode, handle=pkt.start, ecode=body)
        elif pkt.getlayer('ATT_Hdr').opcode == Read_By_Type_Request:
            success, body = self.gatt_server.read_by_type(pkt.start, pkt.end, pkt.uuid,
                                                          self.connection_permission, self.smp.get_connection_encryption_status(connection_handle=self.connection_handle))

            if success:
                self.read_by_type_response = ATT_Hdr() / ATT_Read_By_Type_Response(body)
            else:
                self.error_response = ATT_Hdr() / ATT_Error_Response(request=pkt.getlayer('ATT_Hdr').opcode, handle=pkt.start, ecode=body)


        elif pkt.getlayer('ATT_Hdr').opcode == Read_Request:
            success, body = self.gatt_server.read(pkt.gatt_handle, self.connection_permission, self.smp.get_connection_encryption_status(connection_handle=self.connection_handle))
            if success:
                self.read_response = ATT_Hdr() / ATT_Read_Response(body)
            else:
                self.error_response = ATT_Hdr() / ATT_Error_Response(request=pkt.getlayer('ATT_Hdr').opcode, handle=pkt.gatt_handle, ecode=body)
        
        elif pkt.getlayer('ATT_Hdr').opcode == Read_Blob_Request:
            success, body = self.gatt_server.read_blob(pkt.gatt_handle, pkt.offset, self.connection_permission, self.smp.get_connection_encryption_status(connection_handle=self.connection_handle))
            if success:
                self.read_blob_response = ATT_Hdr() / ATT_Read_Blob_Response(body)
            else:
                self.error_response = ATT_Hdr() / ATT_Error_Response(request=pkt.getlayer('ATT_Hdr').opcode, handle=pkt.gatt_handle, ecode=body)
        elif pkt.getlayer('ATT_Hdr').opcode == Read_Multiple_Request:
            handles = [pkt.handles[i:i+2] for i in range(0, len(pkt.handles), 2)]
            success, body, error_handle = self.gatt_server.read_multiple(handles, self.connection_permission, self.smp.get_connection_encryption_status(connection_handle=self.connection_handle))
            if success:
                self.read_multiple_response = ATT_Hdr() / ATT_Read_Multiple_Response(body)
            else:
                self.error_response = ATT_Hdr() / ATT_Error_Response(request=pkt.getlayer('ATT_Hdr').opcode, handle=error_handle, ecode=body)
        elif pkt.getlayer('ATT_Hdr').opcode == Read_By_Group_Type_Request:
            success, body = self.gatt_server.read_by_group_type(pkt.start, pkt.end, pkt.uuid, self.connection_permission, self.smp.get_connection_encryption_status(connection_handle=self.connection_handle))
            if success:
                self.read_by_group_type_response = ATT_Hdr() / ATT_Read_By_Group_Type_Response(body)
            else:
                self.error_response = ATT_Hdr() / ATT_Error_Response(request=pkt.getlayer('ATT_Hdr').opcode, handle=pkt.start, ecode=body) 
        elif pkt.getlayer('ATT_Hdr').opcode == Write_Request:
            success, body = self.gatt_server.write(pkt.gatt_handle, pkt.data, self.connection_permission, self.smp.get_connection_encryption_status(connection_handle=self.connection_handle))

            if success:
                self.write_response = ATT_Hdr() / ATT_Write_Response()
            else:
                self.error_response = ATT_Hdr() / ATT_Error_Response(request=pkt.getlayer('ATT_Hdr').opcode, handle=pkt.gatt_handle, ecode=body)
        elif pkt.getlayer('ATT_Hdr').opcode == Prepare_Write_Request:
            success, body = self.gatt_server.prepare_write(pkt.gatt_handle, pkt.offset, pkt.data, self.connection_permission, self.smp.get_connection_encryption_status(connection_handle=self.connection_handle))
            if success:
                self.prepare_write_response = ATT_Hdr() / ATT_Prepare_Write_Response(body)
            else:
                self.error_response = ATT_Hdr() / ATT_Error_Response(request=pkt.getlayer('ATT_Hdr').opcode, handle=pkt.gatt_handle, ecode=body)

        elif pkt.getlayer('ATT_Hdr').opcode == Execute_Write_Request:
            success, body = self.gatt_server.execute_write(pkt.flags)
            if success:
                self.execute_write_response = ATT_Hdr() / ATT_Execute_Write_Response()
            else:
                self.error_response = ATT_Hdr() / ATT_Error_Response(request=pkt.getlayer('ATT_Hdr').opcode, handle=pkt.gatt_handle, ecode=body)
        elif pkt.getlayer('ATT_Hdr').opcode == Multiple_Variable_Request:
            pass
        elif pkt.getlayer('ATT_Hdr').opcode == Write_Command:
            success, body = self.gatt_server.write(pkt.gatt_handle, pkt.data, self.connection_permission, self.smp.get_connection_encryption_status(connection_handle=self.connection_handle))
        else:
            pass


    def send_att_handle(self, pkt:Packet):
        # Response packet handle

        # Request packet handle
        att_pkt = pkt.getlayer('ATT_Hdr').getfieldval('opcode')
        if att_pkt == Exchange_MTU_Response:
            if self.exchange_mtu_response!= None:
                return self.exchange_mtu_response
        elif att_pkt == Find_Information_Response:
            if self.find_information_response!= None:
                return self.find_information_response
        elif att_pkt == Find_By_Type_Value_Response:
            if self.find_by_type_value_response!= None:
                return self.find_by_type_value_response
        elif att_pkt == Read_By_Type_Response:
            if self.read_by_type_response!= None:
                return self.read_by_type_response
        elif att_pkt == Read_Response:
            if self.read_response!= None:
                return self.read_response
        elif att_pkt == Read_Blob_Response:
            if self.read_blob_response!= None:
                return self.read_blob_response
        elif att_pkt == Read_Multiple_Response:
            if self.read_multiple_response!= None:
                return self.read_multiple_response
        elif att_pkt == Read_By_Group_Type_Response:
            if self.read_by_group_type_response!= None:
                return self.read_by_group_type_response
        elif att_pkt == Write_Response:
            if self.write_response!= None:
                return self.write_response
        elif att_pkt == Prepare_Write_Response:
            if self.prepare_write_response!= None:
                return self.prepare_write_response
        elif att_pkt == Execute_Write_Response:
            if self.execute_write_response!= None:
                return self.execute_write_response
        elif att_pkt == Multiple_Variable_Response:
            if self.multiple_variable_response!= None:
                return self.multiple_variable_response
        elif att_pkt == Handle_Value_Indication:
            if self.handle_value_indication!= None:
                return self.handle_value_indication
        elif att_pkt == Handle_Value_Confirmation:
            if self.handle_value_confirmation!= None:
                return self.handle_value_confirmation
        elif att_pkt == Multiple_Handle_Value_Notification:
            if self.multiple_handle_value_notification!= None:
                return self.multiple_handle_value_notification
        else:
            pass

