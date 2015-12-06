from utilities import util
from utilities import hashes

import random

# Challenge 34

P_NIST = int(('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
              'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
              '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
              '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
              '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
              'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
              'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
              'fffffffffffff'), 16)
G_NIST =  2
BLOCK_SIZE = 16
MESSAGE = b'Hello World'

# Public parameters
p, g = None, None

# A's parameters:
a     = None
A_A   = None
B_A   = None
s_A   = None

# B's parameters:
b     = None
A_B   = None
B_B   = None
s_B   = None

def send_params_A():
  global g, p, a, A_A
  g = G_NIST
  p = P_NIST
  a = random.randint(0, p-1)
  A_A = pow(g, a, p)
  return (p, g, A_A)

def send_params_B(p, g, A):
  global A_B, b, B_B
  A_B = A
  b = random.randint(0, p-1)
  B_B = pow(g, b, p)
  return B_B

def send_message_A(B):
  global s_A, a, p, B_A
  B_A = B
  s_A = pow(B_A, a, p)
  msg = MESSAGE
  key = hashes.SHA1(util.int_to_bytes(s_A))
  key = util.get_ith_block(key, 0, BLOCK_SIZE)
  iv  = util.random_byte_string(BLOCK_SIZE)
  return (util.cbc_encrypt(msg, key, iv), iv)

def send_message_B(ciphertext, iv):
  global s_B, A_B, b, p
  s_B = pow(A_B, b, p)
  key = hashes.SHA1(util.int_to_bytes(s_B))
  key = util.get_ith_block(key, 0, BLOCK_SIZE)
  plaintext = util.cbc_decrypt(ciphertext, key, iv)
  assert plaintext == MESSAGE
  iv = util.random_byte_string(BLOCK_SIZE)
  return (util.cbc_encrypt(plaintext, key, iv), iv)

if __name__ == '__main__':
  # Simulate Diffie Hellman Protocol
  (p, g, A_A)      = send_params_A()
  B_B              = send_params_B(p, g, A_A)
  (ciphertext, iv) = send_message_A(B_B)
  (ciphertext, iv) = send_message_B(ciphertext, iv)
  print('Successfully executed DH Protocol')

  # Simulate MITM Attack on DH Protocol
  (p, g, A_A)      = send_params_A()
  B_B              = send_params_B(p, g, p)
  (ciphertext, iv) = send_message_A(p)
  (_, _)           = send_message_B(ciphertext, iv)

  s = 0
  key = hashes.SHA1(util.int_to_bytes(s))
  key = util.get_ith_block(key, 0, BLOCK_SIZE)
  plaintext = util.cbc_decrypt(ciphertext, key, iv)
  assert plaintext == MESSAGE
  print('Successfully intercepted plaintext')

