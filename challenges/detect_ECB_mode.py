import base64
import binascii
from utilities import analysis

# Challenge 8

if __name__ == '__main__':
  with open('../data/8.txt', 'r') as f:
    for line in f:
      line = line.strip()
      ciphertext = binascii.unhexlify(line)
      line = f.readline().rstrip()
      if(analysis.detect_ECB_mode(ciphertext)):
        print(line)

