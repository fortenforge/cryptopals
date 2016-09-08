from utilities import util
import DSA_key_recovery as dsa
import random

# Challenge 45

def forge_signature(y):
  (p, q) = (dsa.p, dsa.q)
  z = random.randint(1, 1000)
  r = (pow(y, z, p)) % q
  s = (util.modinv(z, q) * r) % q
  return (r, s)

if __name__ == '__main__':
  message = b'Hello World'
  private_key = random.randint(0, dsa.q)
  public_key = pow(dsa.g, private_key, dsa.p)
  (r1, s1) = dsa.sign(message, private_key)
  assert dsa.verify(message, public_key, (r1, s1))

  # tamper with g by setting it to p + 1
  params = (dsa.p, dsa.q, dsa.p + 1)
  (r2, s2) = forge_signature(public_key)
  assert dsa.verify(message, public_key, (r2, s2), params = params)
  message = b'Goodbye World'
  assert dsa.verify(message, public_key, (r2, s2), params = params)

  print('Successfully forged signature for any message')
