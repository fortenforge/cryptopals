from utilities import util

import binascii
import RSA as rsa

# Challenge 40

# Uses Newton's method
def iroot(k, n):
  u, s = n, n+1
  while u < s:
    s = u
    t = (k-1) * s + n // pow(s, k-1)
    u = t // k
  return s

def broadcast_attack(c1, c2, c3, p1, p2, p3):
  _, n1 = p1
  _, n2 = p2
  _, n3 = p3

  c1 = int(binascii.hexlify(c1), 16)
  c2 = int(binascii.hexlify(c2), 16)
  c3 = int(binascii.hexlify(c3), 16)

  x1 = c1 * n2 * n3 * util.modinv(n2 * n3, n1)
  x2 = c2 * n3 * n1 * util.modinv(n3 * n1, n2)
  x3 = c3 * n1 * n2 * util.modinv(n1 * n2, n3)

  m_cubed = (x1 + x2 + x3) % (n1 * n2 * n3)
  m = iroot(3, m_cubed)
  return util.int_to_bytes(m)


if __name__ == '__main__':
  p1, _ = rsa.generate_keys()
  p2, _ = rsa.generate_keys()
  p3, _ = rsa.generate_keys()

  m = b'rsa br0adca5t att4ck'

  c1 = rsa.encrypt(m, p1)
  c2 = rsa.encrypt(m, p2)
  c3 = rsa.encrypt(m, p3)

  assert broadcast_attack(c1, c2, c3, p1, p2, p3) == m
  print('Successfully determined plaintext')
