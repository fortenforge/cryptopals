import base64
import binascii
import random
from Crypto.Cipher import AES
import util
import analysis

# Challenge 17

def unpadding_validation(string):
    k = string[-1]
    if k == 0:
        raise PaddingError('Inappropriate padding detected')
    
    for i in range(len(string)-1, len(string) - 1 - k, -1):
        if string[i] != k:
            raise PaddingError('Inappropriate padding detected')
    return string[0:len(string)-k]

class PaddingError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

key = b'\x01\x1f\x89\x94\x85{\x8e\xa4\xfa\x8e\xc9\xc3{\x1dz\x06'
iv = b'\xd0\xdf19\x066\xe82\xd5\xe1\x10*\xb4Y*\x15'

plaintext_list = ['MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93']

def cbc_encrypt_special():
    chosen = plaintext_list[random.randint(0, len(plaintext_list)-1)]
    chosen = base64.b64decode(chosen)
    return util.cbc_encrypt(chosen, key, iv)

def cbc_decrypt_special(ciphertext, iv_given):
    AES_obj = AES.new(key, AES.MODE_ECB)
    plaintext = b''
    prev_ciphertext_block = iv_given
    ciphertext_block = iv_given
    for i in range(len(ciphertext)//16):
        ciphertext_block= ciphertext[16*i:16*(i+1)]
        plaintext_block = util.xor(AES_obj.decrypt(ciphertext_block),prev_ciphertext_block)
        plaintext += plaintext_block
        prev_ciphertext_block = ciphertext_block
    unpadding_validation(plaintext)

def cbc_padding_oracle_attack():
    ciphertext = cbc_encrypt_special()
    block_size = 16
    num_blocks = len(ciphertext)//block_size
    plaintext = b''

    current_ciphertext_block = iv

    for b in range(0, num_blocks):
        current_plaintext_block = b''
        failed = False
        wrong_g = b''
        i = 1
        while i < block_size + 1:
            for g in range(256):
                if failed and i == 1 and g == wrong_g:
                    continue
                mod_cipher_block = current_ciphertext_block[:block_size - i]
                guess_current_plain_block = bytes([g]) + current_plaintext_block
                for j in range(block_size - i, block_size):
                    mod_cipher_block += bytes([guess_current_plain_block[j - block_size + i]^current_ciphertext_block[j]^i])
                trial_ciphertext = util.get_ith_block(ciphertext, b, block_size)
                try:
                    cbc_decrypt_special(trial_ciphertext, mod_cipher_block)
                    current_plaintext_block = guess_current_plain_block
                    break
                except PaddingError:
                    pass
            if len(current_plaintext_block) != i:
                failed = True
                wrong_g = current_plaintext_block[-1]
                current_plaintext_block = b''
                i -= 2
            i += 1
        plaintext += current_plaintext_block
        current_ciphertext_block = util.get_ith_block(ciphertext, b, block_size)

    return util.unpadding(plaintext)


print(cbc_padding_oracle_attack())
