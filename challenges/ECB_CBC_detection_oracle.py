import base64
import binascii
import random
from utilities import util, analysis

# Challenge 11

def ecb_cbc_oracle(data):
  prefix = util.random_byte_string(random.randint(5, 10))
  suffix = util.random_byte_string(random.randint(5, 10))
  key    = util.random_byte_string(16)
  data   = util.padding(prefix + data + suffix, 16)
  mode   = random.randint(0,1)
  if mode == 1:
    return util.ecb_encrypt(data, key), mode
  else:
    iv = util.random_byte_string(16)
    return util.cbc_encrypt(data, key, iv), mode

if __name__ == '__main__':
  for i in range(100):
    data = bytes([0]*64)
    cdata, mode = ecb_cbc_oracle(data)
    pmode = analysis.detect_ECB_mode(cdata)
    if pmode == mode:
      print('RIGHT {}'.format(mode))
    else:
      print('WRONG {}'.format(mode))

