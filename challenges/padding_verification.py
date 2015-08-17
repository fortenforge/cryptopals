import base64
import binascii
import random
from Crypto.Cipher import AES

# Challenge 15

def unpadding(string):
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

if __name__ == '__main__':
  strings = ['ICE ICE BABY\x04\x04\x04\x04',
             'ICE ICE BABY\x05\x05\x05\x05',
             'ICE ICE BABY\x01\x02\x03\x04']

  for string in strings:
    try:
      print(unpadding(string))
    except PaddingError as e:
      print(e)

