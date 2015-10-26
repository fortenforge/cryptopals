import binascii
from utilities import util
from utilities import hashes

BLOCK_SIZE = 64
OUTER_PADDING = binascii.unhexlify('5c')*BLOCK_SIZE
INNER_PADDING = binascii.unhexlify('36')*BLOCK_SIZE

def HMAC(hash_function, message, key):
  pad_key = util.zero_padding(key, BLOCK_SIZE)
  return hash_function(util.xor(OUTER_PADDING, pad_key) + hash_function(util.xor(INNER_PADDING, pad_key) + message))

def HMAC_SHA1(message, key):
  return HMAC(hashes.SHA1, message, key)

if __name__ == '__main__':
  print(binascii.hexlify(HMAC_SHA1(b'the quick brown fox', b'YELLOW SUBMARINE')))

