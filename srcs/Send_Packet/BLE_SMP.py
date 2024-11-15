
from typing import List
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.packet import *

from Ble_Test.libs.ble_decrypter.utils.kdf import *
from Ble_Test.libs.scapy.compat import raw
from Ble_Test.libs.scapy.utils import hexdump
from Ble_Test.libs.ble_decrypter.utils.key import *



#smppkts = ['smp_pkts', 'pairing_request_pkt', 'pairing_response_pkt', 'pairing_confirm_pkt', 'pairing_random_pkt', 'pairing_failed_pkt', 'encryption_information_pkt', 'master_identification_pkt', 'identity_information_pkt', 'identity_address_information_pkt', 'signing_information_pkt', 'security_request_pkt', 'pairing_public_key_pkt', 'pairing_dhkey_check_pkt', 'pairing_keypress_notification_pkt']
class BLE_SMP():
    def __init__(self, access_address):
        self.name = "smp_pkts"
        self.access_address = access_address

    def PAIRING_REQUEST_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr()/ SM_Hdr()/ SM_Pairing_Request(iocap = 0x03, oob = 0x00, authentication = 0x2d, max_key_size = 0x10, initiator_key_distribution = 0x04, responder_key_distribution = 0x04)
        return pkt
    def PAIRING_RESPONSE_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr()/ SM_Hdr()/ SM_Pairing_Response(iocap = 0x03, oob = 0x00, authentication = 0x05, max_key_size = 0x10, initiator_key_distribution = 0x07, responder_key_distribution = 0x07)
        return pkt
    def PAIRING_CONFIRM_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr()/ SM_Hdr()/ fuzz(SM_Confirm())
        return pkt
    def PAIRING_RANDOM_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr()/ SM_Hdr()/ SM_Random()
        return pkt
    def PAIRING_FAILED_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr()/ SM_Hdr()/ SM_Failed()
        return pkt
    def ENCRYPTION_INFORMATION_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr()/ SM_Hdr()/ fuzz(SM_Encryption_Information())
        return pkt
    def MASTER_IDENTIFICATION_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr()/ SM_Hdr()/ fuzz(SM_Master_Identification())
        return pkt
    def IDENTITY_INFORMATION_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr()/ SM_Hdr()/ fuzz(SM_Identity_Information())
        return pkt
    def IDENTITY_ADDRESS_INFORMATION_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr()/ SM_Hdr()/ fuzz(SM_Identity_Address_Information())
        return pkt
    def SIGNING_INFORMATION_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr()/ SM_Hdr()/ fuzz(SM_Signing_Information())
        return pkt
    def SECURITY_REQUEST_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr()/ SM_Hdr()/ SM_Security_Request(auth_req = 0x2d)
        return pkt
    def PAIRING_PUBLIC_KEY_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr()/ SM_Hdr()/ SM_Public_Key()
        return pkt
    def PAIRING_DHKEY_CHECK_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr()/ SM_Hdr()/ fuzz(SM_DHKey_Check())
        return pkt
    def PAIRING_KEYPRESS_NOTIFICATION_PKT(self):
        pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr()/ SM_Hdr()/ fuzz(SM_Keypress_Notification())
        return pkt


class BLE_SMP_HANDLE():
    def __init__(self, access_address,advertiser_address,sm:SM):
        self.name = "smppkt"
        self.access_address = access_address
        self.advertiser_address = advertiser_address
        self.sm = sm
    
    def receive_smp_handle(self, pkt:Packet):
        smp_pkt = pkt.getlayer(SM_Hdr)
        if smp_pkt.getfieldval('sm_command') == 0x01:
            self.sm.set_preq(raw(smp_pkt))
        elif smp_pkt.getfieldval('sm_command') == 0x02:
            self.sm.set_prsp(raw(smp_pkt))
        elif smp_pkt.getfieldval('sm_command') == 0x04:
            if self.sm.role:
                self.sm.set_srnd_property(smp_pkt.getfieldval('random'))
                print("srnd " + smp_pkt.getfieldval('random').hex())
            else:
                self.sm.set_mrnd_property(smp_pkt.getfieldval('random'))
                print("mrnd " + smp_pkt.getfieldval('random').hex())
            if self.sm.ecckey_dict == {}:
                self.sm.calculate_STK()
                print("calculate_STK")
            else:
                self.sm.calculate_DHKey_Check()
                print("calculate_DHKey")
        elif smp_pkt.getfieldval('sm_command') == 0x06:
            self.sm.ltk = smp_pkt.getfieldval('ltk')
            self.sm.ll_enc.set_ltk(smp_pkt.getfieldval('ltk')[::-1])

        elif smp_pkt.getfieldval('sm_command') == 0x08:
            self.sm.ll_enc.set_irk(smp_pkt.getfieldval('irk'))
        elif smp_pkt.getfieldval('sm_command') == 0x09:
            pass
        elif smp_pkt.getfieldval('sm_command') == 0x0a:
            self.sm.ll_enc.set_sign_key(smp_pkt.getfieldval('csrk'))

        elif smp_pkt.getfieldval('sm_command') == 0x0c:
            self.sm.device_public_key_x = smp_pkt.getfieldval('key_x')
            print("device_public_key_x " + smp_pkt.getfieldval('key_x').hex())
            self.sm.device_public_key_y = smp_pkt.getfieldval('key_y')
            print("device_public_key_y " + smp_pkt.getfieldval('key_y').hex())

        return pkt

           

    def send_smp_handle(self, pkt:Packet):

        smp_pkt = pkt.getlayer('SM_Hdr')
        if smp_pkt.getfieldval('sm_command') == 0x01:
            self.sm.set_preq(raw(smp_pkt))
           
        elif smp_pkt.getfieldval('sm_command') == 0x02:
            # smp_pkt.setfieldval('sm_command',0x01)
            # self.sm.set_preq(raw(smp_pkt))
            # print(raw(smp_pkt).hex())
            self.sm.set_prsp(raw(smp_pkt))


        elif smp_pkt.getfieldval('sm_command') == 0x03:
            if self.sm.ecckey_dict == {}:
                self.sm.calculate_confirm()
            else:
                self.sm.calculate_secure_confirm_value()
            if self.sm.confirm is None:
                return None
            else:
                return BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr()/ SM_Confirm(confirm=self.sm.confirm)
      
        elif smp_pkt.getfieldval('sm_command') == 0x04:
            if self.sm.role:
                rand = self.sm.mrnd
                print("mrnd " + rand.hex())
            else:
                rand = self.sm.srnd
                print("srnd " + rand.hex())
            
            return_pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr()/SM_Random(random = rand)
            return return_pkt
               
        elif smp_pkt.getfieldval('sm_command') == 0x05:

            pass
        elif smp_pkt.getfieldval('sm_command') == 0x06:
            pass
        elif smp_pkt.getfieldval('sm_command') == 0x0c:
            # key_dict = {"public_key_x":bytes.fromhex("5074875c077d5865abeac9ef63e4445f4279ff823ab401c58f0b7f83fc418fda"),"public_key_y":bytes.fromhex("5e6de136d2dbfe703278165ca73c95eec1f94ae84dfbe8506060f8446a181fac")}
            self.sm.ecckey_dict = ecc_generate_key(curve='P-256')
            pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr()/ SM_Public_Key(key_x = self.sm.ecckey_dict ['public_key_x'][::-1],key_y = self.sm.ecckey_dict ['public_key_y'][::-1])
            return pkt

            # for i in smp_list:           
            #     print(raw(i).hex())
            # return smp_list
        elif smp_pkt.getfieldval('sm_command') == 0x0d:
            if self.sm.dhkey_check is not None:
                pkt = BTLE(access_addr=self.access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr()/ SM_DHKey_Check(dhkey_check = self.sm.dhkey_check[::-1])
                return pkt
            else:
                pass
               


        # sm = self.smp.security_managers[self.advertiser_address.lower()]


    # def SMP_defragment(plist):
    #     """defragment smp datagrams"""
    #     len = 0
    #     crc = 0
    #     PDU = bytes()
    #     packet = BLEMesh_Provisioning_PDU()
    #     for p in plist:
    #         PDU = PDU + bytes(p.payload.payload)
    #     packet.PDU_Padding = PDU[0] >> 6 & 0b11
    #     packet.PDU_Type = PDU[0] & 0b111111
    #     packet.payload = Raw(PDU[1:])
    #     return packet
    # #The PB-GATT bearer MTU (Maximum Transmission Unit) ssize is 20 octets.


     