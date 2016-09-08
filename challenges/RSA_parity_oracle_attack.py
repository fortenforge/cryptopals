from utilities import util

import RSA as rsa
import base64
import binascii

# Challenge 46

public_key = None
private_key = None

KEY_SIZE = 1024

def return_parity(ciphertext):
  global private_key
  c = int(binascii.hexlify(ciphertext), 16)
  return rsa.decrypt_num(c, private_key) % 2

def recover_message(ciphertext):
  global public_key
  e, n = public_key
  c = int(binascii.hexlify(ciphertext), 16)
  x = pow(2, e, n)
  left = 0
  right = n - 1

  for i in range(1, KEY_SIZE + 1):
    y = pow(x, i, n)
    r = (c * y) % n
    b = return_parity(util.int_to_bytes(r))

    l = (left * pow(2, i - 1, n)) % n
    z = (n - 2*l - 1) // pow(2, i)
    mid = left + z

    if b == 0:
      right = mid
    else:
      left = mid + 1

  m = left
  return util.int_to_bytes(m)


if __name__ == '__main__':
  public_key, private_key = rsa.generate_keys(size = KEY_SIZE, e = 65537)
  message = base64.b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
  ciphertext = rsa.encrypt(message, public_key)
  m = recover_message(ciphertext)
  print(m.decode('utf-8'))
