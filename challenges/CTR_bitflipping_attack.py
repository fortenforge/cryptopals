import base64
import binascii
import random
from utilities import util

# Challenge 26

key = b'\x01\x1f\x89\x94\x85{\x8e\xa4\xfa\x8e\xc9\xc3{\x1dz\x06'

def ctr_encrypt_surround(chosen):
  prefix = b'comment1=cooking%20MCs;userdata='
  secret = b';comment2=%20like%20a%20pound%20of%20bacon'
  chosen = chosen.replace(b';', b'').replace(b'=',b'')
  return util.ctr_encrypt(prefix + chosen + secret, key)

def ctr_decrypt_surround(ciphertext):
  plaintext = util.ctr_decrypt(ciphertext, key)
  if plaintext.find(b';admin=true;') != -1:
    print(plaintext)
    return True
  return False

def ctr_bitflipping_attack():
  ciphertext = ctr_encrypt_surround(b'')
  BLOCK_SIZE = 16
  num_blocks = len(ciphertext)//BLOCK_SIZE
  third_block_ciphertext = util.get_ith_block(ciphertext, 2, BLOCK_SIZE)
  third_block_plaintext = b';comment2=%20lik'

  desired_text = util.padding(b';admin=true;', BLOCK_SIZE)
  fixed_third_block = b''

  for i in range(BLOCK_SIZE):
    fixed_third_block += bytes([third_block_plaintext[i]^third_block_ciphertext[i]^desired_text[i]])

  fixed_ciphertext = ciphertext[0:2*BLOCK_SIZE] + fixed_third_block + ciphertext[3*BLOCK_SIZE:]
  print(ctr_decrypt_surround(fixed_ciphertext))

if __name__ == '__main__':
  ctr_bitflipping_attack()

