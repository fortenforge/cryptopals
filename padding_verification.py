import base64
import binascii
import random
from Crypto.Cipher import AES

# Challenge 15

def unpadding(string):
    k = string[-1]
    for i in range(len(string)-1, len(string) - 1 - k, -1):
        if string[i] != k:
            raise PaddingError('Inappropriate padding detected')
    return string[0:len(string)-k]

class PaddingError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
