from utilities import util

import binascii
from Crypto.Util.number import getPrime, getStrongPrime

# Challenge 39

SIZE = 1024

def generate_keys(size = SIZE, e = 3):
  if size < 512:
    p = getPrime(size // 2)
    q = getPrime(size // 2)
  else:
    p = getStrongPrime(size // 2, e)
    q = getStrongPrime(size // 2, e)
  n = p * q
  phi = (p - 1) * (q - 1)
  d = util.modinv(e, phi)
  public_key = (e, n)
  private_key = (d, n)
  return public_key, private_key

def encrypt_num(m, public_key):
  e, n = public_key
  return pow(m, e, n)

def decrypt_num(c, private_key):
  d, n = private_key
  return pow(c, d, n)

def encrypt(m, public_key):
  m_num = int(binascii.hexlify(m), 16)
  c_num = encrypt_num(m_num, public_key)
  return util.int_to_bytes(c_num)

def decrypt(c, private_key):
  c_num = int(binascii.hexlify(c), 16)
  m_num = decrypt_num(c_num, private_key)
  return util.int_to_bytes(m_num)

if __name__ == '__main__':
  plaintext = b'seven times three'
  public_key, private_key = generate_keys()
  ciphertext = encrypt(plaintext, public_key)
  assert decrypt(ciphertext, private_key) == plaintext
  print('Successfully ran RSA')
