import base64
import binascii
import random
from Crypto.Cipher import AES
import util
import analysis

# Challenge 12

def ecb_encrypt_prepend(prefix):
    key = b'\x01\x1f\x89\x94\x85{\x8e\xa4\xfa\x8e\xc9\xc3{\x1dz\x06'
    data = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    data = base64.b64decode(data)
    return util.ecb_encrypt(util.padding(prefix + data, 16), key)

def ecb_chosen_plaintext_attack():
    #first find the blocksize
    block_size = 0
    for block_size in range(5,40):
        block_1 = util.get_ith_block(ecb_encrypt_prepend(b'A'*block_size), 0, block_size)
        block_2 = util.get_ith_block(ecb_encrypt_prepend(b'A'*(block_size+1)), 0, block_size)
        if block_1 == block_2:
            break
    if block_size == 0:
        return False

    #verify that it is ECB mode
    check_ecb = analysis.detect_ECB_mode(ecb_encrypt_prepend(b'A'*4*block_size))
    if not check_ecb:
        return False

    #decryption
    plaintext = b''
    length = len(ecb_encrypt_prepend(b''))
    i = 0
    current_block = b'A'*block_size
    while len(plaintext) < length:
        for j in range(block_size):
            ciphertext_block = util.get_ith_block(ecb_encrypt_prepend(b'A'*(block_size - j - 1)), i, block_size)
            dictionary = {}
            for k in range(256):
                check_block = util.get_ith_block(ecb_encrypt_prepend(current_block[1:block_size] + bytes([k])), 0, block_size)
                dictionary[check_block] = bytes([k])
                
            #deals with padding issues
            if not ciphertext_block in dictionary:
                return plaintext.decode("utf-8")
            
            k = dictionary[ciphertext_block]
            current_block = current_block[1:block_size] + k
        plaintext += current_block
        i += 1

    return plaintext.decode("utf-8")
    
        
print(ecb_chosen_plaintext_attack())
