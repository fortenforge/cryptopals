import base64
import binascii
import random
from utilities import util

# Challenge 27

ERROR_MESSAGE = 'Inappropriate ASCII values'

def ASCII_validation(string):
  for c in string:
    if c >= 128:
      raise ASCIIError(ERROR_MESSAGE)
  return True

class ASCIIError(Exception):
  def __init__(self, value):
    self.value = value
  def __str__(self):
    return repr(self.value)

key = b'YELLOW SUBMARINE'

def cbc_encrypt():
  plaintext = b'The quick brown fox jumps over a lazy dog.'
  return util.cbc_encrypt(plaintext, key, iv = key)

def cbc_decrypt(ciphertext):
  plaintext = util.cbc_decrypt(ciphertext, key, iv = key)
  try:
    ASCII_validation(plaintext)
    return True, plaintext
  except ASCIIError as e:
    return e, plaintext

def cbc_iv_equals_key_attack():
  ciphertext = cbc_encrypt()
  BLOCK_SIZE = 16
  first_block_ciphertext = util.get_ith_block(ciphertext, 0, BLOCK_SIZE)

  constructed_ciphertext = first_block_ciphertext + bytes([0]*BLOCK_SIZE) + first_block_ciphertext + bytes([0]*BLOCK_SIZE*8)

  error, garbled_plaintext = cbc_decrypt(constructed_ciphertext)
  return util.xor(util.get_ith_block(garbled_plaintext, 0, BLOCK_SIZE), util.get_ith_block(garbled_plaintext, 2, BLOCK_SIZE))


if __name__ == '__main__':
  print(cbc_iv_equals_key_attack())

