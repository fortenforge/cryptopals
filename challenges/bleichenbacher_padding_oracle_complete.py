from utilities import util

import RSA as rsa
import binascii

# Challenge 48

public_key = None
private_key = None
B = None

SIZE = 768
k = SIZE // 8

def pkcs_oracle(ciphertext):
  global private_key
  plaintext = rsa.decrypt(ciphertext, private_key)
  return len(plaintext) == k - 1 and plaintext[0] == 2

def pkcs_pad(message):
  assert len(message) <= k - 11
  padding = util.random_byte_string(k - 3 - len(message))
  if 0 in padding:
    return pkcs_pad(message)
  return b'\x00\x02' + padding + b'\x00' + message

def pkcs_unpad(plaintext):
  if len(plaintext) == k:
    plaintext = plaintext[1:]
  assert len(plaintext) == k - 1 and plaintext[0] == 2
  index = plaintext.index(b'\x00')
  return plaintext[index + 1 :]

# returns ceil(a/b)
def ceil_div(a, b):
  x = a // b
  if b * x < a:
    return x + 1
  return x

def compute_homomorphic_c(c, s):
  e, n = public_key
  return (c * pow(s, e, n)) % n

def search_for_pkcs_messages(i, c0, M, s):
  e, n = public_key
  if i == 1: # 2.a
    s_new = ceil_div(n, 3*B)
    while True:
      c = compute_homomorphic_c(c0, s_new)
      if pkcs_oracle(util.int_to_bytes(c)):
        return s_new
      s_new += 1
  elif len(M) > 1: # 2.b
    s_new = s + 1
    while True:
      c = compute_homomorphic_c(c0, s_new)
      if pkcs_oracle(util.int_to_bytes(c)):
        return s_new
      s_new += 1
  else: # 2.c
    (a, b) = M[0]
    r = 2 * ceil_div(b * s - 2 * B, n)
    while True:
      s_left = ceil_div(2 * B + r * n, b)
      s_right = ceil_div(3 * B + r * n, a)
      if s_left >= s_right:
        r += 1
        continue
      for s_new in range(s_left, s_right):
        c = compute_homomorphic_c(c0, s_new)
        if pkcs_oracle(util.int_to_bytes(c)):
          return s_new
      r += 1
  # in theory, we should never get here
  return None

def update_interval(M, s):
  e, n = public_key
  M_new = []

  for (a, b) in M:
    new_a = a
    new_b = b

    r_left = ceil_div(a * s - 3 * B + 1, n)
    r_right = (b * s - 2 * B) // n

    for r in range(r_left, r_right + 1):
      new_left = max(a, ceil_div(2 * B + r * n, s))
      new_right = min(b, (3 * B - 1 + r * n) // s)
      if new_left <= new_right:
        M_new.append((new_left, new_right))
  return M_new

def recover_message(ciphertext):
  # Setup
  global B
  B = pow(2, 8 * (k - 2))

  # Step 1
  # Our plaintext is already PKCS1.5 padded, so the blinding
  # is not necessary
  c = int(binascii.hexlify(ciphertext), 16)
  s = 1
  M = [(2*B, 3*B - 1)]
  i = 1

  while True:
    # Step 2
    s = search_for_pkcs_messages(i, c, M, s)
    # Step 3
    M = update_interval(M, s)
    # Step 4
    if len(M) == 1 and M[0][0] == M[0][1]:
      plaintext = util.int_to_bytes(M[0][0])
      return pkcs_unpad(plaintext)
    i += 1


if __name__ == '__main__':
  public_key, private_key = rsa.generate_keys(size = SIZE)
  message = b'kick it, CC'
  plaintext = pkcs_pad(message)
  ciphertext = rsa.encrypt(plaintext, public_key)
  assert pkcs_oracle(ciphertext)

  guess = recover_message(ciphertext)
  assert guess == message
  print('Successfully recovered message!')
