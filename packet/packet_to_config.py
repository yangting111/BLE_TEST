#！/usr/bin/env python
import os
import sys
import configparser
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__))+'/../libs' )
from scapy.all import rdpcap
from scapy.compat import *
from binascii import hexlify
from scapy.layers.bluetooth4LE import *
from ble_mesh_decrypter.utils.kdf import *

# 获取 Python 文件所在的文件夹路径
dir_path = os.path.dirname(os.path.abspath(__file__))
pcap_file = os.path.join(dir_path, 'esp32-provision-01.pcapng')
config_file = os.path.join(dir_path, 'config.ini')

# 创建一个 ConfigParser 对象
config = configparser.ConfigParser()
# 读取pcap文件
p = rdpcap(pcap_file)

# 添加配置项
config['input'] = {'scan_req': 36, 
                   'connect_ind': 150,
                   'll_version_ind': 157,
                   'll_feature_rsp': 165,
                   'll_connection_update_ind': 179,
                   'provisioning_invite': 303,
                   'provisioning_capabilities': 307,
                   'provisioning_start': 312,
                #    'provisioning_public_key_pdu1': 314,
                #    'provisioning_public_key_pdu2': 316,
                #    'provisioning_confirmation': 2814,
                #    'provisioning_random': 2823,
                #    'provisioning_data':2818,
                #    'provisioning_complete':2811,
                   }
config['device'] = {'initiator_add': '53:2c:5e:4d:c1:40',
                    'target_add': 'e8:31:cd:73:f8:5e',
                    'access_address': '9d4d6550',
                    'adv_ind': False,
                    'scan_rsp': False,
                    'connect_req': False,
                    }
config['provisioning'] = {'PublicKeyProvisionerX':'',
                          'PublicKeyProvisionerY':'',
                          'PrivateKey':'',
                          'PublicKeyDeviceX':'',
                          'PublicKeyDeviceY':'',
                          'ConfirmationInputs':'',
                          'ConfirmationSalt':'',
                          'RandomProvisioner':'',
                          'RandomDevice':'',
                          'ECDHSecret':'',
                          'AuthValue':'',
                    }

def set_publickey():
    global config
    key_set = ecc_generate_key()
    config.set('provisioning', 'PublicKeyProvisionerX', key_set['public_key_x'])    
    config.set('provisioning', 'PublicKeyProvisionerY', key_set['public_key_y'])
    config.set('provisioning', 'PrivateKey', key_set['private_key'] )

for key in config.options('input'):
    config.set('input', key, hexlify(raw(p[config.getint('input', key)-1])[17:-3]+b'\x00\x00\x00').decode('utf-8'))

set_publickey()
# 写入配置文件

with open(config_file, 'w') as config_file:
    config.write(config_file)