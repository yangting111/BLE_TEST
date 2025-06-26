import os
import re
import sys
from tkinter import N
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../")
from ble_decrypter.utils.kdf import *
from Crypto.Cipher import AES
from scapy.all import Packet, raw
import struct
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *


LL_CONNECTION_UPDATE_REQ_OPCODE = 0x00
LL_CHANNEL_MAP_REQ_OPCODE = 0x01
LL_TERMINATE_IND_OPCODE = 0x02
LL_ENC_REQ_OPCODE = 0x03
LL_ENC_RSP_OPCODE = 0x04
LL_START_ENC_REQ_OPCODE = 0x05
LL_START_ENC_RSP_OPCODE = 0x06
LL_UNKNOWN_RSP_OPCODE = 0x07
LL_FEATURE_REQ_OPCODE = 0x08
LL_FEATURE_RSP_OPCODE = 0x09
LL_PAUSE_ENC_REQ_OPCODE = 0x0A
LL_PAUSE_ENC_RSP_OPCODE = 0x0B
LL_VERSION_IND_OPCODE = 0x0C
LL_REJECT_IND_OPCODE = 0x0D
LL_SLAVE_FEATURE_REQ_OPCODE = 0x0E
LL_CONNECTION_PARAM_REQ_OPCODE = 0x0F
LL_CONNECTION_PARAM_RSP_OPCODE = 0x10
LL_REJECT_IND_EXT_OPCODE = 0x11
LL_PING_REQ_OPCODE = 0x12
LL_PING_RSP_OPCODE = 0x13
LL_LENGTH_REQ_OPCODE = 0x14
LL_LENGTH_RSP_OPCODE = 0x15
LL_PHY_REQ_OPCODE = 0x16
LL_PHY_RSP_OPCODE = 0x17
LL_PHY_UPDATE_IND_OPCODE = 0x18




class LL_ENC:
    def __init__(self,access_address=None,role=1):
        self.access_address = access_address    
        self.ltk = None
        self.stk = None
        self.skdm = bytes(8)
        self.ivm = bytes(4)
        self.skds = bytes(8)
        self.ivs = bytes(4)
        self.ediv = os.urandom(2)
        self.rand = os.urandom(8)
        self.skd = bytes(16)
        self.iv = bytes(8)
        self.sk = bytes(16)
        self.conn_master_packet_counter = 0
        self.conn_slave_packet_counter = 0
        self.ll_encryption = False
        self.role = role
        self.irk = os.urandom(16)
       
        self.pirk = None
        self.csrk = os.urandom(16)
        self.pcsrk = None
        self.pediv = None
        self.prand = None
        
        # packet to send
        self.ll_enc_rsp  = None

        self.lesc = False
    def set_pcsrk(self, pcsrk:bytes):
        self.pcsrk = pcsrk
    def get_pcsrk(self):
        return self.pcsrk
    def set_csrk(self, csrk:bytes):
        self.csrk = csrk
    def get_csrk(self):
        return self.csrk
    def set_pediv(self, pediv:bytes):
        self.pediv = pediv
    def get_pediv(self):
        return self.pediv
    def set_pirk(self, pirk:bytes):
        self.pirk = pirk
    def get_pirk(self):
        return self.pirk
    def set_prand(self, prand:bytes):
        self.prand = prand
    def get_prand(self):
        return self.prand
    def set_ediv(self, ediv:bytes):
        self.ediv = ediv
    def get_ediv(self):
        return self.ediv
    def set_rand(self, rand:bytes):
        self.rand = rand
    def get_rand(self):
        return self.rand
    def set_skdm(self, skdm:bytes):
        self.skdm = skdm
    def get_skdm(self):
        return self.skdm
    def set_ivm(self, ivm:bytes):
        self.ivm = ivm
    def get_ivm(self):
        return self.ivm
    def set_skds(self, skds:bytes):
        self.skds = skds
    def get_skds(self):
        return self.skds
    def set_ivs(self, ivs:bytes):
        self.ivs = ivs
    def get_ivs(self):
        return self.ivs
    
    def set_iv(self, iv:bytes):
        self.iv = iv
    def get_iv(self):
        return self.iv
    def set_ltk(self, ltk:bytes):

        self.ltk = ltk
    def get_ltk(self):
        return self.ltk
    
    def set_stk(self, stk:bytes):
        self.stk = stk
    def get_stk(self):
        return self.stk
    
    def set_sk(self, sk:bytes):
        self.sk = sk
    def get_sk(self):
        return self.sk
    
    def set_irk(self, irk:bytes):
        self.irk = irk
    def get_irk(self):
        return self.irk
    def set_lesc(self, lesc:bool):
        self.lesc = lesc
    def get_lesc(self):
        return self.lesc
    
    def set_conn_master_packet_counter(self, conn_master_packet_counter:int):
        self.conn_master_packet_counter = conn_master_packet_counter
    def get_conn_master_packet_counter(self):
        return self.conn_master_packet_counter
    def set_conn_slave_packet_counter(self, conn_slave_packet_counter:int):
        self.conn_slave_packet_counter = conn_slave_packet_counter
    def get_conn_slave_packet_counter(self):
        return self.conn_slave_packet_counter
    
    def generate_skd(self):
        # if self.role == 1:
        #     self.skdm = self.skdm.to_bytes(8, byteorder='big')
        # else:
        #     self.skds = self.skds.to_bytes(8, byteorder='big')
        skd = self.skdm + self.skds
        # print("skd "+skd.hex())
        self.skd = skd
    def generate_iv(self):

        iv = self.ivm+ self.ivs
        # print("iv "+iv.hex())
        self.iv = iv
    def calculate_sk(self):
        if self.ltk is None:
            self.ltk = b"\x00" * 16
        print("ltk "+self.ltk.hex())
        print("skd "+self.skd.hex())
        
        sk = bt_crypto_e(self.ltk,self.skd[::-1])
        print("sk "+sk.hex())
        if self.sk == bytes(16):
            self.sk = sk
        # self.sk = sk



    def ll_encrypted(self, raw_pkt:bytearray):

        access_address = raw_pkt[:4]
        header = raw_pkt[4]  # Get ble header
        length = raw_pkt[5] + 4  # add 4 bytes for the mic
        crc = b'\x00\x00\x00'
        if length > 255:
            length = 255

        pkt_count = bytearray(struct.pack("<Q", self.conn_master_packet_counter)[:5])  # convert only 5 bytes
        pkt_count[4] |= 0x80 if self.role == 1 else 0x00  # Set for master -> slave
        nonce = pkt_count + self.iv
        
    
        aes = AES.new(self.sk, AES.MODE_CCM, nonce=nonce, mac_len=4)  # mac = mic
        aes.update((header & 0xE3).to_bytes(length=1,byteorder="big"))  # Calculate mic over header cleared of NES, SN and MD
        # aes.update((header & 0x03).to_bytes())
        enc_pkt, mic = aes.encrypt_and_digest(raw_pkt[6:-3])  # get payload and exclude 3 bytes of crc
        # enc_pkt, mic = aes.encrypt_and_digest(b'0x06') 
        # print(enc_pkt.hex())
        # print(mic.hex())    
        enc_raw_pkt = access_address + header.to_bytes(length=1,byteorder="big") + length.to_bytes(length=1,byteorder="big") + enc_pkt + mic + crc

        self.conn_master_packet_counter += 1
        return enc_raw_pkt

    def ll_decrypted(self, raw_pkt:bytearray):
        access_address = raw_pkt[:4]
        header = raw_pkt[4]  # Get ble header
        length = raw_pkt[5]  # add 4 bytes for the mic
        if length == 0 or length < 5:
            # ignore empty PDUs
            return raw_pkt
        # Subtract packet length 4 bytes of MIC
        length -= 4

        # Update nonce before decrypting
        pkt_count = bytearray(struct.pack("<Q", self.conn_slave_packet_counter)[:5])  # convert only 5 bytes
        pkt_count[4] |= 0x80 if self.role == 0 else 0x00 
        if raw_pkt is None:
            return
        nonce = pkt_count + self.iv


        # print("iv "+self.iv.hex())
        # print("skd "+self.skd.hex())
        # print("sk "+self.sk.hex())
        if self.ltk is None:
            self.ltk = b"\x00" * 16
        # print("ltk "+self.ltk.hex())
        aes = AES.new(self.sk, AES.MODE_CCM, nonce=nonce, mac_len=4)  # mac = mic
        aes.update((header & 0xE3).to_bytes(length=1,byteorder="big"))  # Calculate mic over header cleared of NES, SN and MD
        # print("raw_pkt "+raw_pkt[6:-4 - 3].hex())
        dec_pkt = aes.decrypt(raw_pkt[6:-4 - 3])  # get payload and exclude 3 bytes of crc
        # print("dec_pkt "+dec_pkt.hex())

        try:
            mic = raw_pkt[6 + length: -3]  # Get mic from payload and exclude crc
            aes.verify(mic)
            self.conn_slave_packet_counter += 1
            return access_address + header.to_bytes(length=1,byteorder="big") + length.to_bytes(length=1,byteorder="big") + dec_pkt + b'\x00\x00\x00'
        except:
            print("MIC Wrong")
            self.conn_slave_packet_counter += 1
            p = access_address + header.to_bytes(length=1,byteorder="big") + length.to_bytes(length=1,byteorder="big") + dec_pkt + b'\x00\x00\x00'
          
            return None     

    def ll_command(self, pkt:Packet, decrpted:bool = False):
        if self.ll_encryption and decrpted == False:
            dencryption_pkt = self.ll_decrypted(raw(pkt))
            de_pkt = BTLE(dencryption_pkt)
            if isinstance(de_pkt, Packet):
                print("--------decrypted packet---------")
                de_pkt.show2()
            
            return de_pkt

        code = pkt.getlayer('BTLE_CTRL').getfieldval('opcode')

        if code == LL_ENC_REQ_OPCODE:
            try:
                self.skdm = pkt.getfieldval('skdm').to_bytes(8, byteorder='little')
                self.ivm = pkt.getfieldval('ivm').to_bytes(4, byteorder='little')
            except AttributeError:
                pass


        elif code == LL_ENC_RSP_OPCODE:
            try:
                self.skds = pkt.getfieldval('skds').to_bytes(8, byteorder='little')
                self.ivs = pkt.getfieldval('ivs').to_bytes(4, byteorder='little')
                self.generate_skd()
                self.generate_iv()
                self.calculate_sk()
               
            except AttributeError:
                pass
        elif code == LL_START_ENC_REQ_OPCODE:

            self.ll_encryption = True
            self.set_conn_master_packet_counter(0)
            self.set_conn_slave_packet_counter(0)

        elif code == LL_START_ENC_RSP_OPCODE:
            pass
        else:
            pass
        return pkt

 
            
    def get_packet(self, packet:Packet):

        result = packet
        if self.ll_encryption:
            # enc_pkt = BTLE(self.ll_encrypted(raw(packet)))
            # result = enc_pkt
            return result

        
        code = packet.getlayer('BTLE_CTRL').getfieldval('opcode')
        if code == LL_ENC_REQ_OPCODE:
            self.skdm = os.urandom(8)
            self.ivm = os.urandom(4)
            result =  BTLE(access_addr = self.access_address)/BTLE_DATA()/ BTLE_CTRL() / LL_ENC_REQ(skdm=self.skdm, ivm=self.ivm)
        elif code == LL_ENC_RSP_OPCODE:
            self.skds = os.urandom(8)
            self.ivs = os.urandom(4)
            self.generate_skd()
            self.generate_iv()
            self.calculate_sk()
            result = BTLE(access_addr = self.access_address)/BTLE_DATA()/ BTLE_CTRL() / LL_ENC_RSP(skds=self.skds, ivs=self.ivs)
        #### test #####
        elif code == LL_START_ENC_RSP_OPCODE:

            if not self.lesc:
                self.ll_encryption = True
                
                self.set_conn_master_packet_counter(0)
                
                self.set_conn_slave_packet_counter(0)
        # #### test #####
        # elif code == LL_START_ENC_REQ_OPCODE:
        #     self.ll_encryption = True
        #### test #####
            
        return result
        # else:
        #     if self.ll_encryption:
        #         return self.ll_encrypted(raw(packet))
            


if __name__ == "__main__":

    ll_enc = LL_ENC()
    data=bytes.fromhex("f2164d18719c3cf9fe4fa5e31ad98318")#(MSO to LSO)
    ll_enc.set_ltk(data)
    ll_enc.set_ivm(bytes.fromhex("df 28 9f 4b".replace(" ",""))[::-1]) #(lso to mso)
    ll_enc.set_ivs(bytes.fromhex("e8 b0 d2 63".replace(" ",""))[::-1]) #(lso to mso)
    ll_enc.set_skdm(bytes.fromhex("22 3b fa 63 b1 45 e2 89".replace(" ",""))[::-1]) #(lso to mso)
    ll_enc.set_skds(bytes.fromhex("20 a3 d8 01 27 ce 77 f6".replace(" ",""))[::-1]) #(lso to mso)
    ll_enc.generate_skd()
    ll_enc.generate_iv()
    ll_enc.calculate_sk() # MSO to LSO
    print(ll_enc.skd.hex()+"\n")
    print(ll_enc.iv.hex()+"\n") 
    print(ll_enc.sk.hex()+"\n")
    print(ll_enc.ltk.hex()+"\n")
    data =bytes.fromhex("3bbcbe1f07054b95d2dcdf5b120c".replace(" ", "")) 

    # enc_data = ll_enc.ll_encrypted(data)
    print(data.hex()+"\n")
    dec_data = ll_enc.ll_decrypted(data)


    # print(enc_data.hex()+"\n")
    print(dec_data.hex()+"\n")   
    

    