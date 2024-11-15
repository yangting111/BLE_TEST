

from Crypto.Cipher import AES
from Crypto.Hash import CMAC, HMAC, SHA256
from Crypto.PublicKey import ECC
 


# 将私钥转换为bytes
def private_key_to_bytes(private_key)-> bytes:
    private_key1 = int(private_key).to_bytes(32, byteorder='big')
    return private_key1
# 将公钥转换为bytes
def public_key_to_bytes(public_key)-> bytes:
    public_key1_x = int(public_key.x).to_bytes(32, byteorder='big')
    public_key1_y = int(public_key.y).to_bytes(32, byteorder='big')
    return public_key1_x, public_key1_y

def ecc_generate_key(curve ='P-256'):
    key_set = {}
    key = ECC.generate(curve= curve)
    key_set['private_key'] = private_key_to_bytes(key.d)
    key_set['public_key_x'], key_set['public_key_y'] = public_key_to_bytes(key.pointQ)
    print(key_set['private_key'].hex())
    print(key_set['public_key_x'].hex())
    print(key_set['public_key_y'].hex())
    return key_set



def bt_crypto_ah(k:bytes,r:bytes):
    """
    # k_data = bytes.fromhex('ec0234a357c8ad05341010a60a397d9b')
    # r_data = bytes.fromhex('708194')
    # byte_data = bt_crypto_ah(k_data, r_data).hex()

    # print(byte_data)
    """

    if k is None or len(k) != 16:
        return False
    # r' = padding || r
    rp = b'\x00' * 13 + r

    # e(k, r')
    encrypted = bt_crypto_e(k, rp)

    # ah(k, r) = e(k, r') mod 2^24
    return encrypted[-3:]

def aes_cmac(key, message):
    """
    Calculate AES CMAC using the Crypto library.

    :param key: The encryption key as bytes. It should be 16, 24, or 32 bytes long.
    :param message: The message to calculate the CMAC for, as bytes.
    :return: The CMAC as a hexadecimal string.
    
    # k_data = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    # m_data = b""
    # byte_data = aes_cmac(k_data, m_data).hex()
    # print(byte_data)
    """
    c = CMAC.new(key, ciphermod=AES)
    c.update(message)
    
    return c.digest()

def u128_xor(a1: bytes, a2: bytes) -> bytes:
    # 确保a1和a2的长度相同
    if len(a1) != len(a2):
        raise ValueError("a1和a2的长度必须相同")
    
    # 对每对字节进行XOR操作，并收集结果
    result = bytes([b1 ^ b2 for b1, b2 in zip(a1, a2)])
    
    return result


def bt_crypto_e(key, plaintext):
    aes = AES.new(key,AES.MODE_ECB)
    return aes.encrypt(plaintext)


def bt_crypto_c1(k, r, preq, pres, iat, ia, rat, ra):
    p1 = pres+preq+rat+iat
    p2 = b"\x00\x00\x00\x00"+ia+ra

    # print(rat)
    # print(iat)

    # print(p1.hex())
    # print(len(p1))
    # print(p2.hex())
    # print(len(p2))
    res = u128_xor(r, p1)
    res = bt_crypto_e(k, res)
    res = u128_xor(res, p2)
    return bt_crypto_e(k, res)


def bt_crypto_s1(k, r1, r2):
    res = r1[8:16] + r2[8:16]
    return bt_crypto_e(k, res)

def bt_crypto_f3(W: bytes, N1: bytes, N2: bytes, R: bytes,IOcap: bytes, A1: bytes, A2: bytes):
    """
    f3(W, N1, N2, R, IOcap, A1, A2) = HMAC-SHA-256W (N1 || N2 || R || IOcap || A1 || A2) / 2

    w = bytes.fromhex('fb3ba2012c7e62466e486e229290175b4afebc13fdccee46')
    n1 = bytes.fromhex('a6e8e7cc25a75f6e216583f7ff3dc4cf')
    n2 = bytes.fromhex('d5cb8454d177733effffb2ec712baeab')
    r = bytes.fromhex('12a3343bb453bb5408da42d20c2d0fc8')
    io_cap = bytes.fromhex('010103')
    a2 = bytes.fromhex('56123737bfce')
    a1 = bytes.fromhex('a713702dcfc1')
    data = bt_crypto_f3(w, n1, n2, r,io_cap, a1, a2)
    print(data.hex())
    """

    # 连接数据
    data = N1 + N2 + R + IOcap + A1 + A2

    # 生成 HMAC
    h = HMAC.new(W, digestmod=SHA256)
    h.update(data)
    hmac_result = h.digest()

    # 截取 HMAC 结果的一半
    

    return hmac_result[:16]
    


def bt_crypto_f4(u:bytes,v:bytes,x:bytes,z:bytes):
    """
    u_data = bytes.fromhex('20b003d2 f297be2c 5e2c83a7 e9f9a5b9eff49111 acf4fddb cc030148 0e359de6'.replace(' ', ''))
    v_data = bytes.fromhex('55188b3d 32f6bb9a 900afcfb eed4e72a59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd'.replace(' ', ''))
    x_data = bytes.fromhex('d5cb8454 d177733e ffffb2ec 712baeab'.replace(' ', ''))
    z_data = b'\x00'
    byte_data = bt_crypto_f4(u_data, v_data, x_data, z_data).hex()
    print(byte_data)
    """
    m = u[:16] + u[16:] + v[:16] + v[16:] + z
    # print(m.hex())

    res = aes_cmac(x, m)
    return res

def bt_crypto_f5( w, n1, n2, a1, a2):
    """
    w_data = bytes.fromhex('ec0234a3 57c8ad05 341010a6 0a397d9b99796b13 b4f866f1 868d34f3 73bfa698'.replace(' ', ''))
    n1_data = bytes.fromhex('d5cb8454 d177733e ffffb2ec 712baeab'.replace(' ', ''))
    n2_data = bytes.fromhex('a6e8e7cc 25a75f6e 216583f7 ff3dc4cf'.replace(' ', ''))
    a1_data = bytes.fromhex('00561237 37bfce'.replace(' ', ''))
    a2_data = bytes.fromhex('00a71370 2dcfc1'.replace(' ', ''))
    mackey, ltk= bt_crypto_f5(w_data, n1_data, n2_data, a1_data, a2_data)
    print(ltk.hex())
    """
    keyid = bytes([0x62, 0x74, 0x6c, 0x65])
    salt = bytes([0xbe, 0x83, 0x60, 0x5a, 0xdb, 0x0b, 0x37, 0x60,
                  0x38, 0xa5, 0xf5, 0xaa, 0x91, 0x83, 0x88, 0x6c])[::-1]
    length = bytes([0x01, 0x00])

    t = aes_cmac(salt, w)


    m = b'\x00'+ keyid + n1 + n2 + a1 + a2 + length

    mackey = aes_cmac(t, m)

    m = b'\x01'+ keyid + n1 + n2 + a1 + a2 + length
    ltk = aes_cmac(t, m)
    return mackey, ltk

def bt_crypto_f6(w, n1, n2, r, io_cap, a1, a2):

    """
    mackey = bytes.fromhex('2965f176 a1084a02 fd3f6a20 ce636e20'.replace(' ', ''))
    n1_data = bytes.fromhex('d5cb8454 d177733e ffffb2ec 712baeab'.replace(' ', ''))
    n2_data = bytes.fromhex('a6e8e7cc 25a75f6e 216583f7 ff3dc4cf'.replace(' ', ''))
    r_data = bytes.fromhex('12a3343b b453bb54 08da42d2 0c2d0fc8'.replace(' ', ''))
    IO_cap_data = bytes.fromhex('010102'.replace(' ', ''))
    a1_data = bytes.fromhex('00561237 37bfce'.replace(' ', ''))
    a2_data = bytes.fromhex('00a71370 2dcfc1'.replace(' ', ''))
    data = bt_crypto_f6(mackey, n1_data, n2_data, r_data, IO_cap_data, a1_data, a2_data)
    print(data.hex())

    """

    m = n1+n2+r+io_cap+a1+a2
    
    # 使用cryptography库创建CMAC对象
    res = aes_cmac(w, m)
    return res

def bt_crypto_g2(u, v, x, y):
    """
    u_data = bytes.fromhex('20b003d2 f297be2c 5e2c83a7 e9f9a5b9eff49111 acf4fddb cc030148 0e359de6'.replace(' ', ''))
    v_data = bytes.fromhex('55188b3d 32f6bb9a 900afcfb eed4e72a59cb9ac2 f19d7cfb 6b4fdd49 f47fc5fd'.replace(' ', ''))

    x_data = bytes.fromhex('d5cb8454 d177733e ffffb2ec 712baeab'.replace(' ', ''))
    y_data = bytes.fromhex('a6e8e7cc 25a75f6e 216583f7 ff3dc4cf'.replace(' ', ''))
    data = bt_crypto_g2(u_data, v_data, x_data, y_data)
    print(data.hex())
    
    """


    m = u + v + y


    res = aes_cmac(x, m)
    val = res[-4:]

    return val

def bt_crypto_h6(w,keyid):
    '''
    w = bytes.fromhex('ec0234a3 57c8ad05 341010a6 0a397d9b'.replace(' ', ''))
    keyid = bytes.fromhex('6c656272'.replace(' ', ''))


    data = bt_crypto_h6(w, keyid)
    print(data.hex())
    '''

    
    value = aes_cmac(w, keyid)
    return value


# if __name__ == "__main__":

#     w = bytes.fromhex('bb 46 0f 30 2f d8 7e c0 81 e5 67 e9 e5 0c a3 cc 72 09 fa a0 ef 74 d2 59 fc 53 15 d8 0d b7 2b e1'.replace(' ', ''))
#     n1_data = bytes.fromhex('a5 a3 93 64 f0 dc 33 35 84 35 24 bc f7 41 0a ff'.replace(' ', ''))
#     n2_data = bytes.fromhex('f7 24 6e d2 62 e4 27 50 5d 7e a2 ff d0 97 64 e3'.replace(' ', ''))
#     # r_data = bytes.fromhex('12a3343b b453bb54 08da42d2 0c2d0fc8'.replace(' ', ''))
#     # IO_cap_data = bytes.fromhex('010102'.replace(' ', ''))
#     a1_data = bytes.fromhex('cd c1 09 cd 9a dd 01'.replace(' ', ''))
#     a2_data = bytes.fromhex('e2 f8 73 cd 31 e8 00'.replace(' ', ''))
#     mackey,data = bt_crypto_f5(w, n1_data, n2_data, a1_data, a2_data)
#     print(mackey.hex())
#     print(data.hex())
    

    


