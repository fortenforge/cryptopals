import base64
import binascii
from Crypto.Cipher import AES
from utilities     import util, analysis

# Challenge 7

if __name__ == '__main__':
  ciphertext = util.open_base64_file('../data/7.txt')
  key = 'YELLOW SUBMARINE'
  plaintext = util.ecb_decrypt(ciphertext, key)
  print(plaintext.decode('utf-8'))
