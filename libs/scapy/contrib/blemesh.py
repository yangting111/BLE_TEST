# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2016 Anmol Sarma <me@anmolsarma.in>

# scapy.contrib.description = Constrained Application Protocol (CoAP)
# scapy.contrib.status = loads

"""

"""

import struct


from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.utils import *
from scapy.packet import Packet, bind_layers, Raw
from scapy.error import warning
from scapy.compat import Any, List, raw
from scapy.fields import (
    XIntField,
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    ConditionalField,
    DestField,
    Emph,
    FieldLenField,
    FieldListField,
    FlagsField,
    IPField,
    IntField,
    MultiEnumField,
    MultipleTypeField,
    PacketListField,
    ShortEnumField,
    ShortField,
    SourceIPField,
    StrField,
    StrFixedLenField,
    StrLenField,
    XByteField,
    XShortField,
    UUIDField,
    LongField,
    ThreeBytesField,
    RawVal
)
from ble_mesh_decrypter.utils import kdf
from ble_mesh_decrypter import *

##################################
#   BLEMesh_Provisioning_Proxy   #
##################################

class BLEMesh_Provisioning_Proxy(Packet):
    name =  "BLEMesh_Provisioning_Proxy"
    fields_desc = [
        BitEnumField("SAR", 0, 2,{0:"complete message",1:"first segment",2:"continuation",3:"last segment"}),
        BitEnumField("Proxy_Type", 0, 6,{0:"Network PDU",1:"Mesh Beacon",2:"Proxy Configuration",3:"Mesh Provisioning PDU"}),
    ]

##########################
#   BLEMesh_Data_Proxy   #
##########################

class BLEMesh_Data_Proxy(Packet):
    name =  "BLEMesh_Data_Proxy"
    fields_desc = [
        BitEnumField("SAR", 0, 2,{0:"complete message",1:"first segment",2:"continuation",3:"last segment"}),
        BitEnumField("Proxy_Type", 0, 6,{0:"Network PDU",1:"Mesh Beacon",2:"Proxy Configuration",3:"Mesh Provisioning PDU"}),
    ]

#####################
#   BLEMesh_Adv     #
#####################
class GP_PDU(Packet):
    name = "Generic Provisioning PDU"
    fields_desc = [
        BitEnumField("Seg_num", 0, 6, {0: "padding", 1: "fragment_1", 2: "fragment_2"}),
        BitEnumField("Control_Format", 0, 2, {0: "transaction_start", 1: "transaction_ack", 2: "transaction_con"})
    ]
class GP_PDU_Transaction_Start(GP_PDU):
    name = "Transactonn_Start"
    Control_Format = 0
    fields_desc = GP_PDU.fields_desc+[
        ShortField("len", 0),
        ByteField("FCS", None)               
    ]
    
class GP_PDU_Transaction_Continuation(GP_PDU):
    name = "Transactonn_Continuation"
    Control_Format = 2  
    fields_desc = GP_PDU.fields_desc
    

class BLEMesh_PBADV(Packet):

    name = "BLEMesh_PBADV"
    #LinkId distincts two device
    #TransNum disticts two fragment packet
    fields_desc = [XIntField("LinkId", 0x01),
                   ByteField("TransNum", 0), 
                   ]
    def fragment(self,pkt, fragsize = 24):
         """Fragment a big PB-ADV datagram"""
         p = pkt
         lst =[]
         if not p.haslayer('BLEMesh_Provisioning_PDU'):
             return p
         total_len = len(raw(p.getlayer('BLEMesh_Provisioning_PDU')))

         nb = total_len//24 + 1
         for i in range(nb):
             if i == 0:
                 f = BLEMesh_PBADV(LinkId=p.LinkId,TransNum=p.TransNum)/GP_PDU_Transaction_Start(Seg_num = nb,len = total_len,FCS = crc8(raw(p.getlayer(BLEMesh_Provisioning_PDU))))/raw(p.getlayer('BLEMesh_Provisioning_PDU'))[0:20]
             elif i == nb-1:
                 f = BLEMesh_PBADV(LinkId=p.LinkId,TransNum=p.TransNum)/GP_PDU_Transaction_Continuation(Seg_num = i)/raw(p.getlayer(BLEMesh_Provisioning_PDU))[20+(i-1)*(fragsize-1):]
             else:
                 f = BLEMesh_PBADV(LinkId=p.LinkId,TransNum=p.TransNum)/GP_PDU_Transaction_Continuation(Seg_num = i)/raw(p.getlayer(BLEMesh_Provisioning_PDU))[20+(i-1)*(fragsize-1):i*(fragsize-1)+20]
             lst.append(f)
         return lst

    
    # def post_build(self, p , pay):
    #     p += pay
    #     if self.FCS is None:
    #         ck = crc8()
        
    #     return p
#########################
#  BLEMesh_Provisioning #
#########################            
class BLEMesh_Provisioning_PDU(Packet):

    name = "BLEMesh_Provisioning_PDU" 
    fields_desc = [
        BitField("PDU_Padding", 0, 2),
        BitEnumField("PDU_Type", 0, 6,
                                {0: "Provisioning Invite",
                                 1: "Provisioning Capabilities",
                                 2: "Provisioning Start",
                                 3: "Provisioning Public Key",
                                 4: "Provisioning Input Complete",
                                 5: "Provisioning Confirmation",
                                 6: "Provisioning Random",
                                 7: "Provisioning Data",
                                 8: "Provisioning Complete",
                                 9: "Provisioning Failed",
                                 }),
    ] 


class Unseg_Control_Message(Packet):

    name = "Unsegmented_Control_Message"
    fields_desc = [
        BitField("SEG", 0, 1),
        BitField("Opcode", 0, 7)
    ]


class Seg_Control_Message(Packet):

    name = "Segmented_Control_Message"
    fields_desc = [
        BitField("SEG", 0, 1),
        BitField("Opcode", 0, 7),
        BitField("RFU", 0, 1),
        BitField("SeqZero", 0, 13),
        BitField("SegO", 0, 5),
        BitField("SegN", 0, 5)
    ]

class Control_Message(Packet):

    name = "Control_Message"
    fields_desc = [
        BitField("SEG", 0, 1),
        BitField("Opcode", 0, 7)        
    ]
      

class Unseg_Access_Message(Packet):

    name = "Unsegmented_Access_Message"
    fields_desc = [
        BitField("SEG", 1, 1),
        BitField("AKF", 0, 1),
        BitField("AID", 0, 6)
    ]
class Seg_Access_Message(Packet):

    name = "Segmented_Access_Message"
    fields_desc = [
        BitField("SEG", 1, 1),
        BitField("AKF", 0, 1),
        BitField("AID", 0, 6),
        BitField("SZMIC", 0, 1),
        BitField("SeqZero", 0, 15),
        BitField("SegO", 0, 5),
        BitField("SegN", 0, 5),
    ]

class Access_Message(Packet):

    name = "Unsegmented_Access_Message"
    fields_desc = [
        BitField("SEG", 1, 1),
        BitField("AKF", 0, 1),
        BitField("AID", 0, 6)
    ]

class Message_Decode(Packet):

    name = "BLEMesh Message Decode"
    
    fields_desc = [BitEnumField("IVI", 0, 1,{0: "ACCEPT", 1: "TRANSMIT"}),
                   BitField("NID", 0, 7), 
                   BitEnumField("CTL", 1, 1, {0: "Access Message and NetMIC 32bit", 1: "Control Message and NetMIC_64bit"}),
                   BitField("TTL", 0, 7),
                   ThreeBytesField("SEQ",20),
                   ShortField("SRC", 0),
                   ShortField("DST", 0),
                   ConditionalField(IntField("NetMIC_32", 0),
                        lambda pkt: pkt.CTL == 0),  # noqa: E501
                   ConditionalField(LongField("NetMIC_64", 0),
                        lambda pkt: pkt.CTL == 1),
    ]
    def post_build(self, p, pay):
        if self.CTL == 0:
            mic = 32
        else:
            mic = 64
        netmic = p[-mic//8:]
        p = p[:-mic//8] + pay + netmic
        return p





class BLEMesh_Message(Packet):

    name = "BLEMesh_Message"

    fields_desc = [BitEnumField("IVI", 0, 1,{0: "ACCEPT", 1: "TRANSMIT"}),
                   BitField("NID", 0, 7),  
                   StrFixedLenField("Obfuscated", b'\x00' * 16, 16),
                   StrLenField("Encrypted_data_NetMIC", None )
                   ]
    



class BLEMesh_Beacon(Packet):

    name = "BLEMesh_Beacon"

    fields_desc = [
                   ByteEnumField("Beacon_Type", 0, {0:"Unprovisioned Device Beacon",1:"Secure Network Beacon"}),
                  ]

class BLEMesh_Unprovisioned_Beacon(BLEMesh_Beacon):

    name = "BLEMesh Unprovisioned Device Beacon"  

    fields_desc = BLEMesh_Beacon.fields_desc+[
                  UUIDField("Device_UUID", None),
                  ShortField("OOB_Information", 0),
                  IntField("URI_Hash", 0)
                  ] 

class BLEMesh_Secure_Network_Beacon(BLEMesh_Beacon):

    name = "BLEMesh Secure Network Beacon" 
    Beacon_Type = 1 

    fields_desc = BLEMesh_Beacon.fields_desc+[
                  BitEnumField("Flag", 0, 8, {0:"Normal operation & Key Refresh False", 1:"Normal operation & Key Refresh True", 2:"IV Update active and Key Refresh False",3:"IV Update active and Key Refresh True"}),
                  LongField("Network_ID", 0),
                  IntField("IV_Index", 0),
                  LongField("Auth_Value", 0)
                  ] 

##################### Packet detail #####################
class Provisioning_Data_Unencrypted(Packet):
    name = "Provisioning_Data_Decode"
    fields_desc = [
        StrFixedLenField("NetworkKey", b'\x00' * 16,16),
        ShortField("KeyIndex", 0),
        ByteField("Flags",0),
        IntField("IVIndex", 0),
        ShortField("UnicastAddress", 0)

    ]

class Provisioning_Invite(BLEMesh_Provisioning_PDU):
    name = "Provisioning_Invite"
    fields_desc = [
        ByteField("ATTENTION_DURATION", 0)
    ]
class Provisioning_Capabilities(BLEMesh_Provisioning_PDU):
    name = "Provisioning_Capabilities"

    fields_desc = [
        ByteField("Num_of_Elements", 1),
        ShortField("Algorithms", 1),
        ByteField("PublicKeyType", 0),
        ByteField("StaticOOBType", 0),
        ByteField("OutputOOBSize", 0),
        ShortField("OutputOOBAction", 0),
        ByteField("InputOOBSize", 0),
        ShortField("InputOOBAction", 0)
    ]

class Provisioning_Start(BLEMesh_Provisioning_PDU):
    name = "Provisioning_Start"

    fields_desc = [
        ByteField("Algorithm", 0),
        ByteField("PublicKey", 0),
        ByteField("AuthMethod", 0),
        ByteField("AuthAction", 0),
        ByteField("AuthSize", 0),
    ]
class Provisioning_Public_Key(BLEMesh_Provisioning_PDU):
    name = "Provisioning_Public_Key"

    fields_desc = [
        StrFixedLenField("PublicKeyX", b'\x00' * 32, 32),
        StrFixedLenField("PublicKeyY", b'\x00' * 32, 32),
    ]
class Provisioning_Confirmation(BLEMesh_Provisioning_PDU):
    name = "Provisioning_Confirmation"

    fields_desc = [
        StrFixedLenField("Confirmation", b'\x00' * 16, 16),
    ]
class Provisioning_Random(BLEMesh_Provisioning_PDU):
    name = "Provisioning_Random"
    fields_desc = [
        StrFixedLenField("Random", b'\x00' * 16, 16),
    ]
class Provisioning_Data(BLEMesh_Provisioning_PDU):
    name = "Provisioning_Data"
    fields_desc = [
        StrFixedLenField("EncryptedData", b'\x00' * 25, 25),
        StrFixedLenField("MIC", b'\x00' * 8, 8),
    ]
class Provisioning_Complete(BLEMesh_Provisioning_PDU):
    name = "Provisioning_Complete"


        

#####################
#  BLEMesh Network  #
#####################
bind_layers(ATT_Write_Command,BLEMesh_Provisioning_Proxy,gatt_handle = 0x0030)
bind_layers(ATT_Handle_Value_Notification,BLEMesh_Provisioning_Proxy,gatt_handle = 0x0032)
bind_layers(ATT_Write_Command,BLEMesh_Data_Proxy,gatt_handle = 0x002a)
bind_layers(ATT_Handle_Value_Notification,BLEMesh_Data_Proxy,gatt_handle = 0x002c)

bind_layers(BLEMesh_PBADV, GP_PDU)
bind_layers(Message_Decode, Access_Message, CTL = 0)
bind_layers(Message_Decode, Control_Message, CTL = 1)
bind_layers(Access_Message, Unseg_Access_Message, SEG = 0)
bind_layers(Access_Message, Seg_Access_Message, SEG = 1)
bind_layers(Control_Message, Unseg_Control_Message, SEG = 0)
bind_layers(Control_Message, Seg_Control_Message, SEG = 1)
bind_layers(EIR_Hdr, BLEMesh_PBADV, type= 0x29)
bind_layers(EIR_Hdr, BLEMesh_Message, type= 0x2a)
bind_layers(EIR_Hdr, BLEMesh_Beacon, type= 0x2b)
bind_layers(BLEMesh_Provisioning_Proxy, BLEMesh_Provisioning_PDU, SAR = 0, Proxy_Type = 3)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Invite, PDU_Type = 0)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Capabilities, PDU_Type = 1)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Start, PDU_Type = 2)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Public_Key, PDU_Type = 3)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Confirmation, PDU_Type = 5)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Random, PDU_Type = 6)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Data, PDU_Type = 7)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Complete, PDU_Type = 8)
bind_layers(BLEMesh_Data_Proxy, BLEMesh_Message, Proxy_Type = 0)



###################
# defragmentation #
###################
#The PB-ADV bearer MTU (Maximum Transmission Unit) ssize is 24 octets.
def PB_ADV_defragment(plist):
    """defragment PB-ADV datagrams"""
    len = 0
    crc = 0
    PDU = bytes()
    packet = BLEMesh_Provisioning_PDU()
    for p in plist:
        PDU = PDU + bytes(p.payload.payload)
    packet.PDU_Padding = PDU[0] >> 6 & 0b11
    packet.PDU_Type = PDU[0] & 0b111111
    packet.payload = Raw(PDU[1:])
    return packet
#The PB-GATT bearer MTU (Maximum Transmission Unit) ssize is 20 octets.
def packet_fragment(pkt,fragsize = 19) -> List[Packet]:
    p = pkt
    lst =[]
    total_len = len(raw(p))
    nb = total_len//fragsize + 1
    for i in range(nb):
        if i == 0:
            f = raw(p)[0:(fragsize)]
        elif i == nb-1:
            f = raw(p)[fragsize+(i-1)*(fragsize):]
        else:
            f = raw(p)[(i)*(fragsize):(i+1)*(fragsize)]
        lst.append(f)
    return lst


def Provisioning_defragment(plist) -> Packet:
    PDU = bytes()
    BLEMesh_Provisioning_PDU
    for p in plist:
        PDU = PDU + bytes(p.payload)
    packet = BLEMesh_Provisioning_PDU(PDU)
    return packet
#def Access_Message_defragment(plist):


###################
#  Message Decode #
###################
# Process Mesh Message Obfuscated and Encrypted_data_NetMIC
def packet_decrypt(pkt):
    en_packet = raw(pkt)
    de_packet = decrypt(en_packet)

    


