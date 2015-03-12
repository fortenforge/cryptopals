import base64
import binascii
from Crypto.Cipher import AES
import util
import analysis

#Challenge 7
ciphertext = util.open_base64_file('7.txt')
key = 'YELLOW SUBMARINE'
plaintext = util.ecb_decrypt(ciphertext, key)
print(plaintext.decode("utf-8"))
