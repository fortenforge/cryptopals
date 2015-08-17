import base64
import binascii
from utilities import util

# Challenge 2

if __name__ == '__main__':
  a = binascii.unhexlify('1c0111001f010100061a024b53535009181c')
  b = binascii.unhexlify('686974207468652062756c6c277320657965')

  print(binascii.hexlify(util.xor(a,b)))

