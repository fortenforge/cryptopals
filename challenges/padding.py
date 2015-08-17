import base64
import binascii
from utilities import util

# Challenge 9

if __name__ == '__main__':
  string = b'YELLOW SUBMARINE'
  print(util.padding(string, 16))

