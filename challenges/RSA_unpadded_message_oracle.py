from utilities import util

import RSA as rsa
import hashlib
import binascii
import random

# Challenge 41

# Server variables
previous_requests = set()
private_key = None

# Public variables
public_key = None

def server_setup():
  global public_key, private_key
  public_key, private_key = rsa.generate_keys()

def server_decrypt(c):
  h = hashlib.sha1(c).hexdigest()
  if h in previous_requests:
    return False
  previous_requests.add(h)

  return rsa.decrypt(c, private_key)

def attack(c):
  e, n = public_key
  c_num = int(binascii.hexlify(c), 16)
  s = random.randint(2, 200)
  c_prime = (pow(s, e, n) * c_num) % n
  p = server_decrypt(util.int_to_bytes(c_prime))
  p_prime = int(binascii.hexlify(p), 16)
  m = (p_prime * util.modinv(s, n)) % n
  return util.int_to_bytes(m)

if __name__ == '__main__':
  server_setup()

  message = b'time in a bottle'
  ciphertext = rsa.encrypt(message, public_key)
  assert message == server_decrypt(ciphertext)

  assert not server_decrypt(ciphertext)
  assert message == attack(ciphertext)
  print('Successfully determined message')
