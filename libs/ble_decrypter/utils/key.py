import os
import logging
from re import T
from tkinter import N

from Ble_Test.libs.ble_decrypter.utils.kdf import *
# from kdf import *




class SM:
    def __init__(self,ll_enc = None, logger_handler = None):
        if logger_handler is not None:
            self.logger = logging.getLogger(logger_handler)
        else:
            self.logger = logging.getLogger(__name__)
        self.tk = bytes.fromhex("00000000000000000000000000000000")
        self.prsp = None
        self.preq = None
        self.ia_type = None
        self.ia = None
        self.ra_type = None
        self.ra = None
        self.io_cap = None
        self.oob = None
        self.mitm = None
        self.bond = None
        self.lesc = None
        self.keypress = None
        self.ct2 = None
        self.rfu = None
        self.mrnd = None
        self.srnd = None
        self.role = 1
        self.confirm = None
        self.mode = 'P-256'
        self.ecckey_dict = {}
        self.device_public_key_x = None
        self.device_public_key_y = None
        self.security_authentication = "Just Works"
        self.binary_passkey = bin(int("0", 16))[2:]
        self.passkey_times = 0
        self.stk = None
        self.r = bytes(16)
        self.dhkey_check = None
        self.ll_enc = ll_enc
        self.iocap = None
        self.mackey = None
        self.ltk =  None

        

        
        # self.logger.debug("mrnd: %s srnd: %s" % (self.mrnd.hex(), self.srnd.hex()))




    def initiate_security_manager_for_connection(self, ia:str, iat:int, ra:str, rat:int, role:int):
        self.set_mrnd_property()
        self.set_srnd_property()
        self.ia = bytes([int(x, 16) for x in ia.split(':')])
        self.ia_type = iat.to_bytes(1, byteorder='big')
        self.ra = bytes([int(x, 16) for x in ra.split(':')])
        self.ra_type = rat.to_bytes(1, byteorder='big')
        self.role = role
        self.ecckey_dict = {}
        self.lesc = False
        
        self.logger.debug("ia: %s ia_type: %s ra: %s ra_type: %s role: %s" % (self.ia.hex(), self.ia_type.hex(), self.ra.hex(), self.ra_type.hex(), self.role))
    
    
    def get_iocapability_property(self):
        return self.io_cap

    def set_oob_property(self, oob):
        self.oob = oob

    def get_oob_property(self):
        return self.oob

    def set_mitm_property(self, mitm):
        self.mitm = mitm

    def get_mitm_property(self):
        return self.mitm

    def set_mrnd_property(self, mrnd = None):
        if mrnd is not None:
            self.mrnd = mrnd
        else:
            self.mrnd = os.urandom(16)
    def get_mrnd_property(self):
        return self.mrnd
    def set_srnd_property(self, srnd = None):
        if srnd is not None:
            self.srnd = srnd
        else:
            self.srnd = os.urandom(16)
    def get_srnd_property(self):
        return self.srnd


    def set_bond_property(self, bond):
        self.bond = bond

    def get_bond_property(self):
        return self.bond

    def set_lesc_property(self, lesc):
        self.lesc = lesc

    def get_lesc_property(self):
        return self.lesc

    def set_keypress_property(self, keypress):
        self.keypress = keypress

    def get_keypress_property(self):
        return self.keypress

    def set_ct2_property(self, ct2):
        self.ct2 = ct2

    def get_ct2_property(self):
        return self.ct2

    def set_rfu_property(self, rfu):
        self.rfu = rfu

    def get_rfu_property(self):
        return self.rfu
    
    def get_ltk_property(self):
        return self.ltk
    def set_ltk_property(self, ltk):
        self.ltk = ltk

    def set_initiator_address(self, address):
        self.ia = address

    def get_initiator_address(self):
        return self.ia

    def set_initiator_address_type(self, address_type):
        self.ia_type = address_type

    def get_initiator_address_type(self):
        return self.ia_type

    def set_receiver_address(self, address):
        self.ra = address

    def get_receiver_address(self):
        return self.ra

    def set_receiver_address_type(self, address):
        self.ra_type = address

    def get_receiver_address_type(self):
        return self.ra_type
    
    def set_prsp(self, prsp):
        self.prsp = prsp
        self.logger.debug("prsp: %s" % self.prsp.hex())
    
    def get_prsp(self):
        return self.prsp
    
    def set_preq(self, preq):
        self.preq = preq
        self.logger.debug("preq: %s" % self.preq.hex())
    def get_preq(self):
        return self.preq
    
    def set_r(self, r):
        self.r = r
        self.logger.debug("r: %s" % self.r.hex())
    def get_r(self):
        return self.r
    


    def calculate_confirm(self):

        """
        sm = SM()
        sm.tk = bytes.fromhex('00000000000000000000000000000000')
        sm.mrnd = bytes.fromhex('5512106d6b12106d7212106d7312106d')
        sm.srnd = bytes.fromhex('5783D52156AD6F0E6388274EC6702EE0')
        sm.prsp = bytes.fromhex('02030001100707')
        sm.preq = bytes.fromhex('0104002d100f0f')
        sm.ia_type = bytes.fromhex('01')
        sm.ia = bytes.fromhex('25152f611477')[::-1]
        sm.ra_type = bytes.fromhex('00')
        sm.ra = bytes.fromhex('1d000050a000')[::-1]
        confirm = sm.calculate_confirm()# Expected: b'
        print(confirm.hex() )
        """
        if self.role:
            rand = self.mrnd
        else:
            rand = self.srnd
        if any(variable is None for variable in [self.tk, self.prsp, self.preq, self.ia_type, self.ia, self.ra_type, self.ra]):
            return None
        else :
            # print(self.ia.hex())
            # print(self.ra.hex())
            # print(self.preq.hex())
            # print(self.prsp.hex())
            self.ia_type = b'\x01'
            # print(self.ia_type.hex())
            self.ra_type = b'\x00'
            # print(self.ra_type.hex())
            # print(rand.hex())
            self.confirm = bt_crypto_c1(self.tk, rand[::-1], self.preq[::-1], self.prsp[::-1], self.ia_type, self.ia, self.ra_type, self.ra)[::-1]
            self.logger.debug("confirm: %s" % self.confirm.hex())
            # print(self.confirm.hex())
            return self.confirm
        
    def calulate_public_key(self):
        self.lesc = True
        self.ll_enc.set_lesc(self.lesc)
        self.ecckey_dict = ecc_generate_key(curve=self.mode)
        self.logger.debug("private_key: %s" % self.ecckey_dict['private_key'].hex())
        self.logger.debug("public_key_x: %s public_key_y: %s" % (self.ecckey_dict['public_key_x'].hex(), self.ecckey_dict['public_key_y'].hex()))
        
        return self.ecckey_dict
    
    def calculate_shared_secret(self):

        private_key_int = int.from_bytes(self.ecckey_dict['private_key'], byteorder='big')
        pub_int_x = int.from_bytes(self.device_public_key_x, byteorder='little')
        pub_int_y = int.from_bytes(self.device_public_key_y, byteorder='little')
        # pub_int_x = int.from_bytes(self.ecckey_dict['public_key_x'][::-1], byteorder='big')
        # pub_int_y = int.from_bytes(self.ecckey_dict['public_key_y'][::-1], byteorder='big')
        private_key = ECC.construct(curve='P-256', d=private_key_int)
        device_public_key = ECC.construct(curve='P-256', point_x=pub_int_x, point_y=pub_int_y)
        shared_key = private_key.d * device_public_key.pointQ
        shared_key_byte = int(shared_key.x).to_bytes(32, byteorder='big')
        return shared_key_byte
    
    def calculate_secure_confirm_value(self):

        if (self.security_authentication == 'Just Works') or (self.security_authentication == 'Numeric Comparison') :
            self.confirm_value = bt_crypto_f4(self.ecckey_dict['public_key_x'], self.device_public_key_x, self.mrnd,z=b'\x00' )
        elif self.security_authentication == 'Passkey Entry':
            self.set_mrnd_property()
            self.confirm_value = bt_crypto_f4(self.ecckey_dict['public_key_x'], self.device_public_key_x, self.mrnd,z = (80 | self.binary_passkey[self.passkey_times]))
            self.passkey_times += 1
        elif self.security_authentication == 'Out of Band':
            self.confirm_value = bt_crypto_f4(self.ecckey_dict['public_key_x'], self.ecckey_dict['public_key_x'], self.mrnd, z=b'\x00' )
        else:
            self.confirm_value = b"\x00" * 16
        return self.confirm_value
    
    def calculate_DHKey_Check(self):
        """
        sm = SM()
        
        w = bytes.fromhex('bb 46 0f 30 2f d8 7e c0 81 e5 67 e9 e5 0c a3 cc 72 09 fa a0 ef 74 d2 59 fc 53 15 d8 0d b7 2b e1'.replace(' ', ''))[::-1]
        n1_data = bytes.fromhex('a5 a3 93 64 f0 dc 33 35 84 35 24 bc f7 41 0a ff'.replace(' ', ''))
        n2_data = bytes.fromhex('f7 24 6e d2 62 e4 27 50 5d 7e a2 ff d0 97 64 e3'.replace(' ', ''))
        # r_data = bytes.fromhex('12a3343b b453bb54 08da42d2 0c2d0fc8'.replace(' ', ''))
        # IO_cap_data = bytes.fromhex('010102'.replace(' ', ''))
        a1_data = bytes.fromhex('cd c1 09 cd 9a dd 01'.replace(' ', ''))
        a2_data = bytes.fromhex('e2 f8 73 cd 31 e8 00'.replace(' ', ''))
        sm.mrnd = n1_data
        sm.srnd = n2_data
        sm.role = 1
        sm.preq = bytes.fromhex('0104000d100f0f')   
        sm.ia = bytes.fromhex('cd c1 09 cd 9a dd')
        sm.ia_type = b'\x01'
        sm.ra = bytes.fromhex('e2 f8 73 cd 31 e8')
        sm.ra_type = b'\x00'
        sm.calculate_DHKey_Check(w)
        mackey 52fa2b372d28a211d7645daad6a612f8
        ltk d7fed6db3a6304a5cd4b91d4fc5412e1
        dhkey_check 260be37b52437615778394cf87e96989
        """
        self.shared_secret = self.calculate_shared_secret()
        w = self.shared_secret   
        # w = shared_secret
        n1 = self.mrnd[::-1]
        n2 = self.srnd[::-1]

        if self.role:
            iocap = self.preq[1:4][::-1]
        else:
            iocap = self.prsp[1:4][::-1]
        r = self.r
        a1 = (self.ia[::-1] + self.ia_type)[::-1]
        a2 = (self.ra[::-1] + self.ra_type)[::-1]  
        # print("w "+w.hex())
        # print("n1 "+n1.hex())
        # print("n2 "+n2.hex())
        # print("iocap "+iocap.hex())
        # print("r "+r.hex())
        # print("a1 "+a1.hex())
        # print("a2 "+a2.hex())
        # MSB ~ LSB
        self.mackey, self.ltk = bt_crypto_f5(w, n1, n2, a1, a2)
        self.logger.debug("mackey: %s ltk: %s" % (self.mackey.hex(), self.ltk.hex()))
        self.ll_enc.set_ltk(self.ltk)
        
        self.dhkey_check = bt_crypto_f6(self.mackey, n1, n2, r, iocap, a1, a2)
        print("dhkey_check "+self.dhkey_check[::-1].hex())

        return self.dhkey_check
        
    
    def calculate_STK(self):
        """
        sm = SM()
        sm.tk = bytes.fromhex('00000000000000000000000000000000')
        
        sm.srnd = bytes.fromhex('000F0E0D0C0B0A091122334455667788')
        sm.mrnd = bytes.fromhex('010203040506070899AABBCCDDEEFF00')
        sm.calculate_STK()
        assert(stk, "9a1fe1f0e8b0f49b5b4216ae796da062")
        """
        STK = bt_crypto_s1(self.tk, self.srnd[::-1], self.mrnd[::-1])
        self.stk = STK
        # print("srnd "+self.srnd.hex())
        # print("mrnd "+self.mrnd.hex())
        # print("STK "+STK.hex())
        self.ll_enc.set_ltk(STK)
        
        return STK
    


    
# if __name__ == "__main__":
#     sm = SM()
    
#     w = bytes.fromhex('bb 46 0f 30 2f d8 7e c0 81 e5 67 e9 e5 0c a3 cc 72 09 fa a0 ef 74 d2 59 fc 53 15 d8 0d b7 2b e1'.replace(' ', ''))[::-1]
#     n1_data = bytes.fromhex('a5 a3 93 64 f0 dc 33 35 84 35 24 bc f7 41 0a ff'.replace(' ', ''))
#     n2_data = bytes.fromhex('f7 24 6e d2 62 e4 27 50 5d 7e a2 ff d0 97 64 e3'.replace(' ', ''))
#     # r_data = bytes.fromhex('12a3343b b453bb54 08da42d2 0c2d0fc8'.replace(' ', ''))
#     # IO_cap_data = bytes.fromhex('010102'.replace(' ', ''))
#     a1_data = bytes.fromhex('cd c1 09 cd 9a dd 01'.replace(' ', ''))
#     a2_data = bytes.fromhex('e2 f8 73 cd 31 e8 00'.replace(' ', ''))
#     sm.mrnd = n1_data
#     sm.srnd = n2_data
#     sm.role = 1
#     sm.preq = bytes.fromhex('0104000d100f0f')   
#     sm.ia = bytes.fromhex('cd c1 09 cd 9a dd')
#     sm.ia_type = b'\x01'
#     sm.ra = bytes.fromhex('e2 f8 73 cd 31 e8')
#     sm.ra_type = b'\x00'
#     sm.calculate_DHKey_Check(w)
# mackey 52fa2b372d28a211d7645daad6a612f8
# ltk d7fed6db3a6304a5cd4b91d4fc5412e1
# dhkey_check 260be37b52437615778394cf87e96989



