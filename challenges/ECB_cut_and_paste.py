import base64
import binascii
import random
from Crypto.Cipher import AES
from utilities     import util

# Challenge 13

PROFILE_KEY = b'\x93m\xf3\x95\xf0%\xc4\xe6Q\xe2z\x90z\xc4\xaf~'
PROFILE_FIELDS = ['email', 'uid', 'role']

def encode_profile(d):
  return '&'.join(['%s=%s' % (k, d[k]) for k in PROFILE_FIELDS])

def decode_profile(encoding):
  result = {}
  for pair in encoding.split('&'):
    kv = pair.split('=')
    if len(kv) == 2:
      key, value = kv
      result[key] = value
  return result

def profile_for(email):
  assert '&' not in email and '=' not in email
  return {
    'email': email,
    'uid': 10,
    'role': 'user',
  }

def encrypt_profile_for(email):
  plaintext = encode_profile(profile_for(email)).encode('utf-8')
  return util.ecb_encrypt(util.padding(plaintext, 16), PROFILE_KEY)

def decrypt_profile(crypt):
  plaintext = util.ecb_decrypt(crypt, PROFILE_KEY)
  return decode_profile(util.unpadding(plaintext).decode('utf-8'))

if __name__ == '__main__':
  BLOCK_SIZE = 16
  admin = util.padding(b'admin', BLOCK_SIZE)
  admin_block  = util.get_ith_block(encrypt_profile_for('A'*(BLOCK_SIZE - len('email=')) + admin.decode('utf-8')), 1, BLOCK_SIZE)
  first_block  = util.get_ith_block(encrypt_profile_for('fooka@bar.com'), 0, BLOCK_SIZE)
  second_block = util.get_ith_block(encrypt_profile_for('fooka@bar.com'), 1, BLOCK_SIZE)
  admin_ciphertext = first_block + second_block + admin_block
  print(decrypt_profile(admin_ciphertext))

