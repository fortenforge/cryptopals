import base64
import binascii
from utilities import util

# Challenge 10

if __name__ == '__main__':
  ciphertext = util.open_base64_file('../data/10.txt')
  key = 'YELLOW SUBMARINE'
  plaintext = util.cbc_decrypt(ciphertext, key)
  print(plaintext.decode('utf-8'))

