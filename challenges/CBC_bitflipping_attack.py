import base64
import binascii
import random
from utilities import util

# Challenge 16

def unpadding_validation(string):
  k = string[-1]
  for i in range(len(string)-1, len(string) - 1 - ord(k), -1):
    if string[i] != k:
      raise PaddingError('Inappropriate padding detected')
  return string[0:len(string)-ord(k)]

class PaddingError(Exception):
  def __init__(self, value):
    self.value = value
  def __str__(self):
    return repr(self.value)

key = b'\x01\x1f\x89\x94\x85{\x8e\xa4\xfa\x8e\xc9\xc3{\x1dz\x06'

def cbc_encrypt_surround(chosen):
  prefix = b'comment1=cooking%20MCs;userdata='
  secret = b';comment2=%20like%20a%20pound%20of%20bacon'
  chosen = chosen.replace(b';', b'').replace(b'=',b'')
  return util.cbc_encrypt(prefix + chosen + secret, key)

def cbc_decrypt_surround(ciphertext):
  plaintext = util.cbc_decrypt(ciphertext, key)
  if plaintext.find(b';admin=true;') != -1:
    print(plaintext)
    return True
  return False

def cbc_bitflipping_attack():
  ciphertext = cbc_encrypt_surround(b'')
  BLOCK_SIZE = 16
  num_blocks = len(ciphertext)//BLOCK_SIZE
  first_block_ciphertext = util.get_ith_block(ciphertext, 0, BLOCK_SIZE)
  second_block_plaintext = b'%20MCs;userdata='

  desired_text = util.padding(b';admin=true;', BLOCK_SIZE)
  fixed_first_block = b''

  for i in range(BLOCK_SIZE):
    fixed_first_block += bytes([second_block_plaintext[i]^first_block_ciphertext[i]^desired_text[i]])

  fixed_ciphertext = fixed_first_block + ciphertext[BLOCK_SIZE:]
  print(cbc_decrypt_surround(fixed_ciphertext))

if __name__ == '__main__':
  cbc_bitflipping_attack()

