#!/usr/bin/python 
import os
import platform
import sys
from binascii import hexlify
from time import sleep
from aalpy.utils import load_automaton_from_file




print(sys.path)
# extra libs
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__))+'/../libs' )

print(sys.path)
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.layers.inet import *
from scapy.contrib.blemesh import *
from scapy.compat import *
from scapy.utils import *
from scapy.fields import *
from ble_mesh_decrypter.utils.kdf import *
from uuid import UUID
import binascii

public_key_x='ffbfaaf9f50883922e19b41e2c5a7145eae3d99daaed9fc7b5507a70833869b9'
public_key_y='77c3aa238010ffb9231b5e3f3210ff0a345dc2e0891e37c28a3a01ee3e839b17'
# Convert the string to the desired format
converted_string_x = bytes.fromhex(public_key_x)
converted_string_y = bytes.fromhex(public_key_y)


scan_req = BLEMesh_PBADV(LinkId = 76354974, TransNum = 129)/GP_PDU()/BLEMesh_Provisioning_PDU(PDU_Type = 3)/converted_string_x/converted_string_y
# scan_req = BLEMesh_PBADV(LinkId = 76354974, TransNum = 129)/GP_PDU_Transaction_Start(Seg_num = 0)
# lst = scan_req.fragment()
# a = GP_PDU_Transaction_Continuation()
# pdu = defragment(lst)
# b = BLEMesh_Unprovisioned_Beacon(Device_UUID = UUID("dea00001-6c97-11d1-8271-00a02442df7d"), OOB_Information = 11, URI_Hash = 0xd97478b3)
# c = Message_Decode()
# crc = crc8(raw(scan_req.getlayer(BLEMesh_Provisioning_PDU)))
# print(crc)
# print(raw(c))
# crc8(scan_req)
# scan_req1.show2()
# print(lst[0])
# hexdump(scan_req)
# print(raw(scan_req))
s = Provisioning_Capabilities()
print(raw(s))
# a = binascii.hexlify(raw(scan_req)).decode('utf-8')
# print(type(a))

# print(bytes.fromhex("68110edeecd83c3010a05e1b23a926023da75d25ba91793736"))
# print(type(raw((scan_req))))
# sul=SulInterface(config_file=config_file)
# driver = NRF52Dongle(port_name='/dev/ttyACM1', debug=True, logs=True, logs_pcap=True, pcap_filename='test.pcap',config_file=config_file)
# receive_data = sul.connect_req(timeout=0.5)

# receive_data = sul.ll_feature_req(timeout=0.5)
# receive_data = sul.ll_feature_rsp(timeout=0.5)

# s = BTLE(bytes.fromhex(configread.get('input', 'connect_ind')))
# s = BTLE(access_addr=0xeb1d25) / BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Handle_Value_Notification()
# s = BTLE(access_addr=0x25841254) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(max_tx_bytes=247 + 4, max_rx_bytes=247 + 4)
# s = Provisioning_Public_Key(PublicKeyX = bytes.fromhex(configread.get('provisioning', 'publickeyprovisionerx')), PublicKeyY = bytes.fromhex(configread.get('provisioning', 'publickeyprovisionery')))

# lst = PB_GATT_Provisioning_fragment(s)

# for i in lst:
#     print(i.hex())
#     print(len(i))

# print(s.PublicKeyX.hex())



# print(hexdump(s))
# print(s.show())
# s.getlayer(BTLE_DATA)
# p = raw(s)[:-3]
# # print(p[4:].hex())
# a = p + BTLE.compute_crc(p[4:])

# print(a.hex())
# driver.raw_send(bytes.fromhex(configread.get('input', 'scan_req')))
# driver.receive_data( min_attempts=10, max_attempts=50)





