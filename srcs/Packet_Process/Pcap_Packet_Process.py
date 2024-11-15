from calendar import c
import sys
import os


sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../libs/")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")

from scapy.utils import RawPcapReader
from scapy.all import *
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
from Ble_Test.libs.ble_decrypter.utils.ll_enc import *

from Ble_Test.libs.ble_decrypter.utils import key
from scapy.contrib.blemesh import *
# Process original pcap file
import configparser
from binascii import hexlify, unhexlify

class Packet_Process():
    def __init__(self, packet_to_config = True,access_address = None):
        self.pkt_count = {'adv_pkt_count':0,'ll_pkt_count':0,'smp_pkt_count':0,'l2cap_pkt_count':0,'att_pkt_count':0}
        self.config_file_path = None
        self.count = 0
        self.packet_to_config = packet_to_config
        self.adv_pkt_type = set()
        self.ll_pkt_type = set()
        self.l2cap_pkt_type = set()
        self.att_pkt_type = set()
        self.sm_pkt_type = set()
        self.adv_bonds_dict = BTLE_ADV.upper_bonds()
        self.ll_bonds_dict = BTLE_CTRL.upper_bonds()
        self.att_bonds_dict = ATT_Hdr.upper_bonds()
        self.l2cap_bonds_dict = L2CAP_CmdHdr.upper_bonds()
        self.smp_bonds_dict = SM_Hdr.upper_bonds()
        self.access_address = access_address
        if packet_to_config:
            self.config = configparser.ConfigParser()
        # 去除重复数据包
    def add_unique_value(self,section, key, value):

        if not self.config.has_section(section):
            self.config.add_section(section)
        for existing_key in self.config[section]:
            if self.config[section][existing_key] == value:
                return
        self.config.set(section, key, value)


    def process_pcap(self, file_name):
        self.config_file_path = '/home/yangting/Documents/Ble_Test/srcs/Config_File/' + file_name.split('/')[-2]+"/"+file_name.split('/')[-1].split('.')[0] + '.ini'
        print('Opening {}...'.format(file_name))
        for (pkt_data, pkt_metadata) in RawPcapReader(file_name):

            direction = (pkt_data[8] >> 1) & 1

            if direction == 1:
                pkt = BTLE(pkt_data[17:])

                if pkt.haslayer('BTLE_ADV'):
                    # packet type 
                    self.pkt_count['adv_pkt_count'] += 1
                    adv_pkt = pkt.getlayer('BTLE_ADV')
                    pkt_type = adv_pkt.getfieldval('PDU_type')

                    if(self.packet_to_config):
                        self.add_unique_value("adv_pkts",str(pkt_metadata.tslow)+"_"+ self.adv_bonds_dict[pkt_type], hexlify(raw(adv_pkt)).decode('utf-8'))
                        self.adv_pkt_type.add(pkt_type)

                    
                elif pkt.haslayer('BTLE_CTRL'):
                    # packet type 
                    self.pkt_count['ll_pkt_count'] += 1
                    ll_pkt = pkt.getlayer('BTLE_CTRL')
                    pkt_type = ll_pkt.getfieldval('opcode')
                    
                    if(self.packet_to_config):
                        try:
                            self.add_unique_value("ll_pkts",str(pkt_metadata.tslow)+"_"+ self.ll_bonds_dict[pkt_type], hexlify(raw(ll_pkt)).decode('utf-8'))
                            self.ll_pkt_type.add(pkt_type)
                        except Exception as e:
                            pass
                elif pkt.haslayer('ATT_Hdr'):
                    # packet type 
                    att_pkt = pkt.getlayer('ATT_Hdr')
                    if att_pkt.haslayer('BLEMesh_Data_Proxy'):
                        pass
                    elif att_pkt.haslayer("BLEMesh_Provisioning_Proxy"):
                        pass
                    else:
                        self.pkt_count['att_pkt_count'] += 1
                        pkt_type = att_pkt.getfieldval('opcode')
                        

                    if self.packet_to_config:
                        self.add_unique_value("att_pkts",str(pkt_metadata.tslow)+"_"+ self.att_bonds_dict[pkt_type], hexlify(raw(att_pkt)).decode('utf-8'))
                        self.att_pkt_type.add(pkt_type)
 
                elif pkt.haslayer('L2CAP_CmdHdr'):
                    # packet type 
                    self.pkt_count['l2cap_pkt_count'] += 1
                    l2cap_pkt = pkt.getlayer('L2CAP_CmdHdr')
                    pkt_type = l2cap_pkt.getfieldval('code')
                    
                    if self.packet_to_config:
                        self.add_unique_value("l2cap_pkts",str(pkt_metadata.tslow)+"_"+ self.l2cap_bonds_dict[pkt_type], hexlify(raw(l2cap_pkt)).decode('utf-8'))
                        self.l2cap_pkt_type.add(pkt_type)
                        # if not self.config.has_section("l2cap_pkts"):
                        #     self.config.add_section("l2cap_pkts")
                        
                        # for existing_key in self.config["l2cap_pkts"]:
                        #     if self.config["l2cap_pkts"][existing_key] == hexlify(raw(l2cap_pkt)).decode('utf-8'):
                        #         pass
                        #     else:
                        #         self.config.set("l2cap_pkts",str(self.pkt_count['l2cap_pkt_count'])+"_"+ self.l2cap_bonds_dict[pkt_type], hexlify(raw(l2cap_pkt)).decode('utf-8'))

                elif pkt.haslayer('SM_Hdr'):
                    # packet type 
                    self.pkt_count['smp_pkt_count'] += 1
                    sm_pkt = pkt.getlayer('SM_Hdr')
                    pkt_type = sm_pkt.getfieldval('sm_command')
                    
                    if self.packet_to_config:
                        self.add_unique_value("smp_pkts",str(pkt_metadata.tslow)+"_"+ self.smp_bonds_dict[pkt_type], hexlify(raw(sm_pkt)).decode('utf-8'))
                        self.sm_pkt_type.add(pkt_type)
                        # if not self.config.has_section("sm_pkts"):
                        #     self.config.add_section("sm_pkts")

                        # for existing_key in self.config["sm_pkts"]:
                        #     if self.config["sm_pkts"][existing_key] == hexlify(raw(sm_pkt)).decode('utf-8'):
                        #         pass                        
                        #     else:
                        #         self.config.set("sm_pkts",str(self.pkt_count['smp_pkt_count'])+"_"+ self.smp_bonds_dict[pkt_type], hexlify(raw(sm_pkt)).decode('utf-8'))

        print('adv_pkt_count: {}, pkt_type: {}, pkt_name: {}'.format(self.pkt_count['adv_pkt_count'],len(self.adv_pkt_type),", ".join(self.adv_bonds_dict[i] for i in self.adv_pkt_type)))
        print('ll_pkt_count: {}, pkt_type: {}, pkt_name: {}'.format(self.pkt_count['ll_pkt_count'], len(self.ll_pkt_type),", ".join(self.ll_bonds_dict[i] for i in self.ll_pkt_type)))
        print('smp_pkt_count: {}, pkt_type: {}, pkt_name: {}'.format(self.pkt_count['smp_pkt_count'],len(self.sm_pkt_type),", ".join(self.smp_bonds_dict[i] for i in self.sm_pkt_type)))
        print('l2cap_pkt_count: {}, pkt_type: {}, pkt_name: {}'.format(self.pkt_count['l2cap_pkt_count'],len(self.l2cap_pkt_type),", ".join(self.l2cap_bonds_dict[i] for i in self.l2cap_pkt_type)))
        print('att_pkt_count: {}, pkt_type: {}, pkt_name: {}'.format(self.pkt_count['att_pkt_count'],len(self.att_pkt_type),", ".join(self.att_bonds_dict[i] for i in self.att_pkt_type)))
        if self.packet_to_config:
            with open(self.config_file_path, 'w') as configfile:
                self.config.write(configfile)

    def read_config_packet(self, file_name, section):
        pkt_dict = {}
        pkt = None
        self.config.read(file_name)
         
        if not self.config.has_section(section):
            return pkt_dict
        for key, value in self.config.items(section):
            packet_raw = unhexlify(value)
            if section == 'll_pkts':
                pkt = BTLE_CTRL(packet_raw)
                if str(pkt.getfieldval('opcode')) in pkt_dict:
                    origin = pkt_dict[str(pkt.getfieldval('opcode'))]
                    pkt_dict[str(pkt.getfieldval('opcode'))] = []
                    if isinstance(origin, list):
                        pkt_dict[str(pkt.getfieldval('opcode'))].extend(origin)
                    else:
                        pkt_dict[str(pkt.getfieldval('opcode'))].append(origin)
                        pkt_dict[str(pkt.getfieldval('opcode'))].append(self.ll_packet_append(pkt.lastlayer()))
                else:
                    pkt_dict[str(pkt.getfieldval('opcode'))] = self.ll_packet_append(pkt.lastlayer())
            elif section == 'adv_pkts':
                pkt = BTLE_ADV(packet_raw)
                if str(pkt.getfieldval('PDU_type')) in pkt_dict:
                    origin = pkt_dict[str(pkt.getfieldval('PDU_type'))]
                    pkt_dict[str(pkt.getfieldval('PDU_type'))] = []
                    if isinstance(origin, list):
                        pkt_dict[str(pkt.getfieldval('PDU_type'))].extend(origin)
                    else:
                        pkt_dict[str(pkt.getfieldval('PDU_type'))].append(origin)
                        pkt_dict[str(pkt.getfieldval('PDU_type'))].append(self.adv_packet_append(pkt.lastlayer()))
                else:
                    pkt_dict[str(pkt.getfieldval('PDU_type'))] = self.adv_packet_append(pkt.lastlayer())
            elif section == 'smp_pkts':
                pkt = SM_Hdr(packet_raw)
                if str(pkt.getfieldval('sm_command')) in pkt_dict:
                    origin = pkt_dict[str(pkt.getfieldval('sm_command'))]
                    pkt_dict[str(pkt.getfieldval('sm_command'))] = []
                    if isinstance(origin, list):
                        pkt_dict[str(pkt.getfieldval('sm_command'))].extend(origin)
                    else:
                        pkt_dict[str(pkt.getfieldval('sm_command'))].append(origin)
                        pkt_dict[str(pkt.getfieldval('sm_command'))].append(self.smp_packet_append(pkt.lastlayer()))
                else:
                    pkt_dict[str(pkt.getfieldval('sm_command'))] = self.smp_packet_append(pkt.lastlayer())
            
            elif section == 'l2cap_pkts':
                pkt = L2CAP_CmdHdr(packet_raw)
                if str(pkt.getfieldval('code')) in pkt_dict:
                    origin = pkt_dict[str(pkt.getfieldval('code'))]
                    pkt_dict[str(pkt.getfieldval('code'))] = []
                    if isinstance(origin, list):
                        pkt_dict[str(pkt.getfieldval('code'))].extend(origin)
                    else:
                        pkt_dict[str(pkt.getfieldval('code'))].append(origin)
                        pkt_dict[str(pkt.getfieldval('code'))].append(self.l2cap_packet_append(pkt.lastlayer()))
                else:
                    pkt_dict[str(pkt.getfieldval('code'))] = self.l2cap_packet_append(pkt.lastlayer())
            elif section == 'att_pkts':
                pkt = ATT_Hdr(packet_raw)
                if str(pkt.getfieldval('opcode')) in pkt_dict:
                    origin = pkt_dict[str(pkt.getfieldval('opcode'))]
                    pkt_dict[str(pkt.getfieldval('opcode'))] = []
                    if isinstance(origin, list):
                        pkt_dict[str(pkt.getfieldval('opcode'))].extend(origin)
                    else:
                        pkt_dict[str(pkt.getfieldval('opcode'))].append(origin)
                        pkt_dict[str(pkt.getfieldval('opcode'))].append(self.att_packet_append(pkt.lastlayer()))
                else:
                    pkt_dict[str(pkt.getfieldval('opcode'))] = self.att_packet_append(pkt.lastlayer())
        return pkt_dict
    def read_pre_packet(self, file_name,tslow):
        pkt_list = []
        pkt = None
        self.config.read(file_name) 
        for section in self.config.sections():
            for key, value in self.config.items(section):
                packet_raw = unhexlify(value)
                key1 = key.split('_')[0]
                if int(key1) < int(tslow):
                    if section == 'll_pkts':
                        pkt = BTLE_CTRL(packet_raw)
                        pkt_list.append((int(key1),self.ll_packet_append(pkt.lastlayer())))

                    elif section == 'adv_pkts':
                        pkt = BTLE_ADV(packet_raw)
                        pkt_list.append((int(key1),self.adv_packet_append(pkt.lastlayer())))
                       
                    elif section == 'smp_pkts':
                        pkt = SM_Hdr(packet_raw)
                        pkt_list.append((int(key1),self.smp_packet_append(pkt.lastlayer())))
                       
                    elif section == 'l2cap_pkts':
                        pkt = L2CAP_CmdHdr(packet_raw)
                        pkt_list.append((int(key1),self.l2cap_packet_append(pkt.lastlayer())))

                    elif section == 'att_pkts':
                        pkt = ATT_Hdr(packet_raw)
                        pkt_list.append((int(key1),self.att_packet_append(pkt.lastlayer())))
                    
        sorted_pkt_list = sorted(pkt_list)
        return sorted_pkt_list

    def smp_packet_append(self,packet:Packet):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr()/ packet
        return pkt
    def att_packet_append(self,packet:Packet):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / packet
        return pkt
    def l2cap_packet_append(self,packet:Packet):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() /L2CAP_Hdr()/ L2CAP_CmdHdr()/ packet
        return pkt
    def ll_packet_append(self,packet:Packet):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / BTLE_CTRL() / packet
        return pkt
    def adv_packet_append(self,packet:Packet):
        pkt = BTLE(access_addr=self.access_address) / BTLE_ADV() / packet
        return pkt 
    


        
if __name__ == '__main__':
    s = Packet_Process()
    s.process_pcap(file_name = "/home/yangting/Documents/Ble_Test/packet/Microchip/unpairing.pcapng")
    pkt_dict = s.read_config_packet(file_name="/home/yangting/Documents/Ble_Test/srcs/Config_File/Microchip/unpairing_8_26.ini", section='ll_pkts')

