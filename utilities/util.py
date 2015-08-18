import base64
import binascii
import random
import struct
import math
from Crypto.Cipher import AES

def open_base64_file(filename):
    f = open(filename)
    b64_text = ""
    line = f.readline().rstrip()
    while line != '\n' and line != '':
        b64_text += line
        line = f.readline().rstrip()
    f.close()
    return base64.b64decode(b64_text)

def xor(a, b):
    return bytes([ai^bi for (ai,bi) in zip(a,b)])

def single_char_xor(c, k):
    p = b''
    for i in range(len(c)):
        p += bytes([c[i]^k])
    return p

def repeating_key_xor(c, k):
    p = b''
    l = len(k)
    for i in range(len(c)):
        p += bytes([c[i]^k[i%l]])
    return p

def random_byte_string(length):
    return bytes([random.randint(0, 2**8-1) for i in range(length)])

def padding(string, length):
    k = length - (len(string) % length)
    return string + k*bytes([k])

def unpadding(string):
    k = string[-1]
    return string[0:len(string)-k]

def get_ith_block(data, i, block_size):
    if (i+1)*block_size > len(data):
        return data[i*block_size:]
    return data[i*block_size:(i+1)*block_size]

def ecb_encrypt(plaintext, key):
    AES_obj = AES.new(key, AES.MODE_ECB)
    return AES_obj.encrypt(plaintext)

def ecb_decrypt(ciphertext, key):
    AES_obj = AES.new(key, AES.MODE_ECB)
    return AES_obj.decrypt(ciphertext)

def cbc_encrypt(plaintext, key, iv = bytes([0])*16):
    AES_obj = AES.new(key, AES.MODE_ECB)
    ciphertext = b''
    plaintext = padding(plaintext, 16)
    ciphertext_block = iv
    for i in range(len(plaintext)//16):
        plaintext_block  = plaintext[16*i:16*(i+1)]
        ciphertext_block = AES_obj.encrypt(xor(plaintext_block, ciphertext_block))
        ciphertext += ciphertext_block
    return ciphertext

def cbc_decrypt(ciphertext, key, iv = bytes([0])*16):
    AES_obj = AES.new(key, AES.MODE_ECB)
    plaintext = b''
    prev_ciphertext_block = iv
    ciphertext_block = iv
    for i in range(len(ciphertext)//16):
        ciphertext_block= ciphertext[16*i:16*(i+1)]
        plaintext_block = xor(AES_obj.decrypt(ciphertext_block),prev_ciphertext_block)
        plaintext += plaintext_block
        prev_ciphertext_block = ciphertext_block
    return unpadding(plaintext)

def ctr_encrypt(plaintext, key, nonce = 0):
    AES_obj = AES.new(key, AES.MODE_ECB)
    nonce = struct.pack('<Q', nonce)
    ciphertext = b''
    block_size = 16
    for i in range(math.ceil(len(plaintext)/block_size)):
        counter = struct.pack('<Q', i)
        keystream = AES_obj.encrypt(nonce + counter)
        p_block = get_ith_block(plaintext, i, block_size)
        ciphertext += xor(p_block, keystream)
    return ciphertext

def ctr_decrypt(ciphertext, key, nonce = 0):
    return ctr_encrypt(ciphertext, key, nonce)