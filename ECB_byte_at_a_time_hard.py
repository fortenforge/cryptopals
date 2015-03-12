import base64
import binascii
import random
from Crypto.Cipher import AES
import util
import analysis

# Challenge 14

def ecb_encrypt_surround(chosen):
    key = b'\x01\x1f\x89\x94\x85{\x8e\xa4\xfa\x8e\xc9\xc3{\x1dz\x06'
    prefix = b'\xc0NF\x87\xd69\xb7\x11n\\\xd5H\x0c\xee\xe6\xd2\xe9k\xdc\xb9^\x7fk\xff\xectG2gRx\xb2Y5\xd7\xf2}\xecM\xee&\xc7'
    secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    secret = util.base64.b64decode(secret)
    return util.ecb_encrypt(util.padding(prefix + chosen + secret, 16), key)

def ecb_chosen_plaintext_attack():
    #find block size
    block_size = 16

    #find length of prefix
    empty_ciphertext = ecb_encrypt_surround(b'')
    fixed_ciphertext = ecb_encrypt_surround(b'A')
    current_empty_block = util.get_ith_block(empty_ciphertext, 0, block_size)
    current_fixed_block = util.get_ith_block(fixed_ciphertext, 0, block_size)
    i = 0
    while current_empty_block == current_fixed_block:
        i += 1
        current_empty_block = util.get_ith_block(empty_ciphertext, i, block_size)
        current_fixed_block = util.get_ith_block(fixed_ciphertext, i, block_size)

    trans_index = i

    number_of_chars = 0

    fixed_block = util.get_ith_block(ecb_encrypt_surround(b'A'*block_size*2), trans_index + 1, block_size)
    for i in range(block_size + 1, 2*block_size+1):
        potential_fixed_block = util.get_ith_block(ecb_encrypt_surround(b'A'*i), trans_index+1, block_size)
        if potential_fixed_block == fixed_block:
            number_of_chars = i - block_size
            break
    
    #decryption
    plaintext = b''
    length = len(ecb_encrypt_surround(b''))
    i = trans_index
    current_block = b'A'*block_size
    while len(plaintext) < length:
        for j in range(block_size):
            ciphertext_block = util.get_ith_block(ecb_encrypt_surround(b'A'*number_of_chars + b'A'*(block_size - j - 1)), i + 1, block_size)
            dictionary = {}
            for k in range(256):
                check_block = util.get_ith_block(ecb_encrypt_surround(b'A'*number_of_chars + current_block[1:block_size] + bytes([k])), trans_index + 1, block_size)
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
