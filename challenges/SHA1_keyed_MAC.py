from utilities import hashes
import binascii

# Challenge 28

def SHA1_keyed_MAC(key, message):
  return binascii.hexlify(hashes.SHA1(key + message))

if __name__ == '__main__':
  key = b'YELLOW SUBMARINE'
  message = b'The quick brown fox jumps over a lazy dog'
  print(SHA1_keyed_MAC(key, message))
