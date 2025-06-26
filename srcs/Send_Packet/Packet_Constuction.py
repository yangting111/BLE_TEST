
from typing import List


from Ble_Test.srcs.Send_Packet.BLE_LL import BLE_LL, BLE_LL_HANDLE
from Ble_Test.srcs.Send_Packet.BLE_ADV import BLE_ADV, BLE_ADV_HANDLE
from Ble_Test.srcs.Send_Packet.BLE_SMP import BLE_SMP, BLE_SMP_HANDLE
from Ble_Test.srcs.Send_Packet.BLE_L2CAP import BLE_L2CAP, BLE_L2CAP_HANDLE
from Ble_Test.srcs.Send_Packet.BLE_ATT import BLE_ATT, BLE_ATT_HANDLE
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.all import Raw, hexdump
from Ble_Test.libs.ble_decrypter.utils.key import *
from Ble_Test.libs.ble_decrypter.utils.ll_enc import *



class Packet_Constuction():
    def __init__(self,access_address,advertiser_address,master_address,iat,rat,role,rx_len,tx_len,logger_handler=None,key_path=None):
        self.access_address = access_address
        self.advertiser_address = advertiser_address
        self.master_address = master_address
        self.advpkt_dict = {}
        self.llpkt_dict = {}
        self.smppkt_dict = {}
        self.l2cappkt_dict = {}
        self.attpkt_dict = {}
        self.ll_enc = LL_ENC(access_address=self.access_address,role=role)
        self.sm = SM(ll_enc=self.ll_enc,logger_handler=logger_handler)
        self.sm.initiate_security_manager_for_connection(master_address,iat,advertiser_address,rat,role)
        self.connection_handle = 0 
        self.adv_handle = BLE_ADV_HANDLE()
        self.ll_handle = BLE_LL_HANDLE(ll_enc=self.ll_enc)
        self.att_handle = BLE_ATT_HANDLE(self.access_address,self.advertiser_address,self.sm,self.connection_handle)
        self.smp_handle  = BLE_SMP_HANDLE(self.access_address,self.advertiser_address,self.sm)
        self.l2cap_handle = BLE_L2CAP_HANDLE()
        self.rx_len = rx_len
        self.tx_len = tx_len
        self.encrypted = False
        self.key_path = key_path
        self.iat = iat
        self.rat = rat
        self.packet_list = []
        if self.key_path:
            if os.path.exists(key_path):
                old_file_path = key_path + '.old'
                os.rename(key_path, old_file_path)
            with open(key_path, 'w') as f:
                f.write("Master_address: " + self.master_address + "\n")
                f.write("-------------------------------------------\n")

            

    def get_pkts(self,pkt_list:list):
        pkt_type = pkt_list[0]
        pkts_list = {}
        if pkt_type == 'll_pkts':
            for pkt in pkt_list[1:]:
                try:
                    pkts_list[pkt] = getattr(BLE_LL(self.access_address), pkt.upper())()
                except AttributeError:
                    print(f"Error: {pkt} is not a valid packet type")
                self.llpkt_dict = pkts_list
        elif pkt_type == 'adv_pkts':
            for pkt in pkt_list[1:]:
                try:
                    pkts_list[pkt] = getattr(BLE_ADV(self.advertiser_address,self.master_address,self.iat,self.rat), pkt.upper())()
                    
                except AttributeError:
                    print(f"Error: {pkt} is not a valid packet type")
                self.advpkt_dict = pkts_list
        elif pkt_type == 'smp_pkts':
            for pkt in pkt_list[1:]:
                try:
                    pkts_list[pkt] = getattr(BLE_SMP(self.access_address), pkt.upper())()
                except AttributeError:
                    print(f"Error: {pkt} is not a valid packet type")
                self.smppkt_dict = pkts_list
        elif pkt_type == 'l2cap_pkts':
            for pkt in pkt_list[1:]:
                try:
                    pkts_list[pkt] = getattr(BLE_L2CAP(self.access_address), pkt.upper())()
                except AttributeError:
                    print(f"Error: {pkt} is not a valid packet type")
                self.l2cappkt_dict = pkts_list
        elif pkt_type == 'att_pkts':
            for pkt in pkt_list[1:]:
                try:
                    pkts_list[pkt] = getattr(BLE_ATT(self.access_address), pkt.upper())()
                except AttributeError:
                    print(f"Error: {pkt} is not a valid packet type")
                self.attpkt_dict = pkts_list
        # print(pkts_list)
        return pkts_list   
    
    def set_pkts(self,pkt_type:str,data_list:list):

        if pkt_type == 'll_pkts':
            pkt_list = self.llpkt_dict
        elif pkt_type == 'adv_pkts':
            pkt_list = self.advpkt_dict
        elif pkt_type == 'smp_pkts':
            pkt_list = self.smppkt_dict
        elif pkt_type == 'l2cap_pkts':
            pkt_list = self.l2cappkt_dict
        elif pkt_type == 'att_pkts':
            pkt_list = self.attpkt_dict
        else:
            print(f"Error: {pkt_type} is not defined")
            return None
#       [pkt,layer,field,value]
        for data in data_list:
            # print(data)
            if len(data)<3:
                pass
            elif data[2]== 'raw':
                try:         
                    pkt_list[data[0]] = pkt_list[data[0]]/Raw(data[3])
                except AttributeError:
                    print(f"Error: {data[3]} is not a valid type, please input bytes value")    
            else:

                try:
                    pkt_list[data[0]].getlayer(data[1]).setfieldval(data[2], data[3])
                except AttributeError:
                    print(f"Error: set_pkts failed")
        return pkt_list
    

    def set_pkt(self,pkt:Packet,data_list:list):
        for data in data_list:
            if len(data)<3:
                pass
            elif data[2]== 'raw':
                try:         
                    pkt = pkt/Raw(data[3])
                except AttributeError:
                    print(f"Error: {data[3]} is not a valid type, please input bytes value")    
            else:
                try:
                    pkt.getlayer(data[1]).setfieldval(data[2], data[3])
                except AttributeError:
                    print(f"Error: set_pkts failed")
        return pkt

    
    
    def get_pkt(self, pkt_name:str,pkt_dict:dict={}):


        result = None
        if pkt_name in self.advpkt_dict:
            pkt = self.advpkt_dict[pkt_name]
            if isinstance(pkt, Packet):
                PDU_type = pkt.getfieldval('PDU_type')
                if str(PDU_type) in pkt_dict:
                        self.advpkt_dict[pkt_name] = pkt_dict[str(PDU_type)]
            result = self.advpkt_dict[pkt_name]
        elif pkt_name in self.llpkt_dict:
            pkt = self.llpkt_dict[pkt_name]
            if isinstance(pkt, Packet):
                try:
                    opcode = pkt.getfieldval('opcode')

                except AttributeError:
                    if pkt_name == 'll_empty_pkt':
                        result = pkt
                        return result
                    else:
                        print(f"Error: {pkt_name} is not defined")
                        return None
                    
                if str(opcode) in pkt_dict:
                    self.llpkt_dict[pkt_name] = pkt_dict[str(opcode)]
            result = self.llpkt_dict[pkt_name]
        elif pkt_name in self.smppkt_dict:
            pkt = self.smppkt_dict[pkt_name]
            if isinstance(pkt, Packet):
                sm_command = pkt.getfieldval('sm_command')
                if str(sm_command) in pkt_dict:
                    self.smppkt_dict[pkt_name] = pkt_dict[str(sm_command)]
            result = self.smppkt_dict[pkt_name]
        elif pkt_name in self.l2cappkt_dict:
            pkt = self.l2cappkt_dict[pkt_name]
            if isinstance(pkt, Packet):
                code = pkt.getfieldval('code')
                if str(code) in pkt_dict:
                    self.l2cappkt_dict[pkt_name] = pkt_dict[str(code)]
            result = self.l2cappkt_dict[pkt_name]
        elif pkt_name in self.attpkt_dict:
            pkt = self.attpkt_dict[pkt_name]
            if isinstance(pkt, Packet):
                opcode = pkt.getfieldval('opcode')
                if str(opcode) in pkt_dict:
                    self.attpkt_dict[pkt_name] = pkt_dict[str(opcode)]
            result = self.attpkt_dict[pkt_name]
            

        if result is None:
            print(f"Error: {pkt_name} is not defined")
        else:
            result = self.send_packet_handler(result)    
        return result
    

    def get_packet_pattern(self,packet_name:str):
        if packet_name in list(self.advpkt_dict.keys()):
            return self.advpkt_dict[packet_name]
        elif packet_name in list(self.llpkt_dict.keys()):
            return self.llpkt_dict[packet_name]
        elif packet_name in list(self.smppkt_dict.keys()):
            return self.smppkt_dict[packet_name]
        elif packet_name in list(self.l2cappkt_dict.keys()):
            return self.l2cappkt_dict[packet_name]
        elif packet_name in list(self.attpkt_dict.keys()):
            return self.attpkt_dict[packet_name]
        else:
            return None


    def receive_packet_handler(self,pkt:Packet):
        decrypted = False

        if self.encrypted:
            print("aaaaaaaaaaa+Encrypted")
            result = self.ll_handle.receive_ll_handle(pkt)
            
            if isinstance(result, Packet):
                pkt = result
                decrypted = True
        pkt = self.receive_length_check(pkt)
        if not isinstance(pkt, Packet):
            return None
        

        if pkt.haslayer('BTLE_ADV'):

            result = self.adv_handle.receive_adv_handle(pkt)
        elif pkt.haslayer('BTLE_CTRL'):
            
            result = self.ll_handle.receive_ll_handle(pkt,decrypted)

            if isinstance(result, Packet) and result.haslayer('BTLE_CTRL'):
                if result.getlayer('BTLE_CTRL').getfieldval('opcode') == 0x05:
                    self.set_encryption(True)
                return result
            if isinstance(result, list):
                return result
        elif pkt.haslayer('BTLE_ATT'):
            
            result = self.att_handle.receive_att_handle(pkt)
        elif pkt.haslayer('L2CAP_CmdHdr'):
            
            result = self.l2cap_handle.receive_l2cap_handle(pkt)
        elif pkt.haslayer('SM_Hdr'):
            
            result = self.smp_handle.receive_smp_handle( pkt)
            return result
        else:
            # ##############test Realtek###################
            # self.set_encryption(True)

            # pkt = self.ll_enc.ll_decrypted(raw(pkt))
            # self.set_encryption(False)
            # return BTLE(pkt)
            # ##############test Realtek###################
            return pkt
    def encryption_check(self,pkt:Packet):

        if self.encrypted and self.ll_enc.ll_encryption:

            print("aaaaaaaaaaa+Encrypted")
            packet = BTLE(self.ll_enc.ll_encrypted(raw(pkt)))

        else:
            packet = pkt
        return packet
            





    def send_packet_handler(self,pkt:Packet):


        result = None
    

        if pkt.haslayer('BTLE_ADV'):
            
            result = self.adv_handle.send_adv_handle(pkt)
            

        elif pkt.haslayer('BTLE_CTRL'):
                ####test######
            # if pkt.getlayer('BTLE_CTRL').getfieldval('opcode') == 0x06:
                
            #     self.encrypted = True
                ####test######
                
            
            packet = self.ll_handle.send_ll_handle(pkt)
            if isinstance(packet, Packet):
                result = self.packet_length_check(packet)

        elif pkt.haslayer('ATT_Hdr'):
            
            # packet = self.att_handle.send_att_handle(pkt)
            result = pkt
            print(result)
            

        elif pkt.haslayer('L2CAP_CmdHdr'):
            
            packet = self.l2cap_handle.send_l2cap_handle(pkt)

        elif pkt.haslayer('SM_Hdr'):
            
            packet = self.smp_handle.send_smp_handle(pkt)
            if isinstance(packet, Packet):
                result = self.packet_length_check(packet)

        
        return result

        
    def find_section(self, packet_name:str):
        if packet_name in list(self.advpkt_dict.keys()):
            return 'adv_pkts'
        elif packet_name in list(self.llpkt_dict.keys()):
            return 'll_pkts'
        elif packet_name in list(self.smppkt_dict.keys()):
            return 'smp_pkts'
        elif packet_name in list(self.l2cappkt_dict.keys()):
            return 'l2cap_pkts'
        elif packet_name in list(self.attpkt_dict.keys()):
            return 'att_pkts'
        else:
            return None
        
    def set_encryption(self,encrypted:bool):
        self.encrypted = encrypted
        self.ll_enc.ll_encryption = encrypted

    def packet_length_check(self,pkt:Packet):
        # pkt.show2()
        if pkt.haslayer('L2CAP_Hdr'):
            l2cap_pkt = pkt.getlayer("L2CAP_Hdr")
            if len(raw(l2cap_pkt)) > self.tx_len:
                pkt_list = self.pkt_fragment(l2cap_pkt)
                return pkt_list
            else:
                return pkt
        else:
            return pkt

    def receive_length_check(self,pkt:Packet):
        
        
        if pkt.haslayer('BTLE_DATA'):
            if pkt.haslayer("L2CAP_Hdr") and pkt.getlayer('L2CAP_Hdr').getfieldval('len') > pkt.getlayer('BTLE_DATA').getfieldval('len'):
                self.packet_list.append(pkt)
                print(hexdump(raw(pkt)))
                
            
            elif len(self.packet_list) > 0 and pkt.getlayer('BTLE_DATA').getfieldval('LLID') == 0x01:
                    
                    self.packet_list.append(pkt)
                    print(hexdump(raw(pkt)))
                    sum_len = sum([i.getlayer('BTLE_DATA').getfieldval('len') for i in self.packet_list]) 

                    # packet_list中BTLE_DATA的len之和和L2CAP_Hdr的len相等时，进行重组
                    if sum_len == (self.packet_list[0].getlayer('L2CAP_Hdr').getfieldval('len') + 4):
                        
                        result = self.pkt_reassemble(self.packet_list)
                        print("receive_length_check----------------")
                        # print(hexdump(raw(result)))

                        result.show2()
                        self.packet_list = []
                        return result
            else:
                return pkt






    def pkt_fragment(self,pkt) -> List[Packet]:
        p = pkt
        lst =[]
        total_len = len(raw(p))
        nb = total_len//self.tx_len + 1
        for i in range(nb):
            if i == 0:
                f = BTLE(access_addr=self.access_address) / BTLE_DATA(LLID = 0x02,SN = 1,NESN = 1, MD = 1)/raw(p)[0:(self.tx_len)]
            elif i == nb-1:
                f = BTLE(access_addr=self.access_address) / BTLE_DATA(LLID = 0x01,SN = 1,NESN = 1)/raw(p)[self.tx_len+(i-1)*(self.tx_len):]
            else:
                f = BTLE(access_addr=self.access_address) / BTLE_DATA(LLID = 0x01,SN = 0,NESN = 0, MD =1)/raw(p)[(i)*(self.tx_len):(i+1)*(self.tx_len)]
            lst.append(f)
        return lst
    def pkt_reassemble(self,pkt_list:List[Packet]) -> Packet:
        #重组数据包
        p = raw(pkt_list[0])[:-3]
        for i in range(1,len(pkt_list)):
            p = p + raw(pkt_list[i].getlayer('BTLE_DATA').payload)
        p = p + raw(b'\x00\x00\x00')
        return BTLE(p)


    def save_key(self):
        if self.key_path:

            key1 = self.ll_enc.__dict__
            key2 = self.sm.__dict__
            with open(self.key_path, 'a') as f:
                f.write("LL_ENC\n")
                f.write("-------------------------------------------\n")
                for key, value in key1.items():
                    if isinstance(value, bytes):
                        f.write(f"{key}: {value.hex()}\n")
                    elif isinstance(value, int) or isinstance(value, str):
                        f.write(f"{key}: {value}\n")
                    elif value is None:
                        f.write(f"{key}: None\n")
                    else:
                        pass
                    
                f.write("SM\n")
                f.write("-------------------------------------------\n")
                for key, value in key2.items():
                    if isinstance(value, bytes):
                        f.write(f"{key}: {value.hex()}\n")
                    elif isinstance(value, int) or isinstance(value, str):
                        f.write(f"{key}: {value}\n")
                    elif value is None:
                        f.write(f"{key}: None\n")
                    else:
                        pass
                f.write("-------------------------------------------\n")


                        