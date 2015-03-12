import base64
import binascii
import util

# Challenge 10

ciphertext = util.open_base64_file('10.txt')
key = 'YELLOW SUBMARINE'
plaintext = util.cbc_decrypt(ciphertext, key)
print(plaintext.decode("utf-8"))
