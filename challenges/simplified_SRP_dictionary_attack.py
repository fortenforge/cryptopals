from utilities import util
from utilities import HMAC

import random
import hashlib

# Challenge 38

N = int(('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
         'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
         '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
         '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
         '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
         'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
         'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
         'fffffffffffff'), 16)
g = 2
password = b'hunter2'

# C's parameters
a = None
A_C = None

# S's parameters
b = None
B = None
A_S = None
salt = None
v = None

def SHA256_hex(m):
  return hashlib.sha256(m).hexdigest()

def SHA256(m):
  return hashlib.sha256(m).digest()

def initialize_S():
  global salt, v
  salt = util.random_byte_string(32)
  xH = SHA256_hex(salt + password)
  x = int(xH, 16)
  v = pow(g, x, N)

def send_params_C():
  global a, A_C
  a = random.randint(0, N-1)
  A_C = pow(g, a, N)
  return A_C

def send_params_S(A):
  global b, A_S, B
  A_S = A
  b = random.randint(0, N-1)
  B = pow(g, b, N) % N
  return salt, B

def send_hmac_C(salt, B):
  xH = SHA256_hex(salt + password)
  x = int(xH, 16)
  u = int(SHA256_hex(util.int_to_bytes(A_C) + util.int_to_bytes(B)), 16)
  S = pow(B, a + u * x, N)
  K = SHA256(util.int_to_bytes(S))
  return HMAC.HMAC(SHA256, K, salt)

def verify_hmac_S(hmac):
  u = int(SHA256_hex(util.int_to_bytes(A_S) + util.int_to_bytes(B)), 16)
  S = pow((A_S * pow(v, u, N)), b, N)
  K = SHA256(util.int_to_bytes(S))
  return hmac == HMAC.HMAC(SHA256, K, salt)

def dictionary_attack(hmac, salt, A, B):
  global b
  u = int(SHA256_hex(util.int_to_bytes(A) + util.int_to_bytes(B)), 16)
  with open('/usr/share/dict/words', 'r') as f:
    for word in f:
      for d in range(10):
        guess = (word.strip() + str(d)).encode('utf-8')
        xH = SHA256_hex(salt + guess)
        x = int(xH, 16)
        v = pow(g, x, N)
        S = pow((A * pow(v, u, N)), b, N)
        K = SHA256(util.int_to_bytes(S))
        if hmac == HMAC.HMAC(SHA256, K, salt):
          return guess

if __name__ == '__main__':
  # Simulate Secure Remote Password
  initialize_S()
  A         = send_params_C()
  (salt, B) = send_params_S(A)
  hmac      = send_hmac_C(salt, B)
  response  = verify_hmac_S(hmac)
  assert response
  print('Successfully executed simplified SRP Protocol')

  # Simulate MITM Secure Remote Password
  initialize_S()
  A         = send_params_C()
  (salt, B) = send_params_S(A)
  hmac      = send_hmac_C(salt, B)
  response  = verify_hmac_S(hmac)
  assert response

  # Offline dictinary attack
  guess = dictionary_attack(hmac, salt, A, B)
  print(guess)
  assert guess == password
  print('Successfully guessed password')
