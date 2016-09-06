from utilities import util

import binascii
import re
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Util import asn1

def faulty_verifier(message, signature, key):
  n = key.n
  e = 3

  s = int(binascii.hexlify(signature), 16)
  m = util.int_to_bytes(pow(s, e, n))

  r = re.match(br'01(ff)+00', binascii.hexlify(m))
  if not r:
    return False
  asn = binascii.unhexlify(binascii.hexlify(m)[r.end():])
  try:
    sequence = asn1.DerSequence()
    sequence.decode(asn)
    assert len(sequence) == 2
    assert len(sequence[1]) == 20 + 2
    found_hash = sequence[1][2:]
  except (ValueError, IndexError) as e:
    return False

  expected_hash = SHA.new(message).digest()
  return expected_hash == found_hash

def legit_verifier(message, signature, key):
  h = SHA.new(message)
  verifier = PKCS1_v1_5.new(key)
  return verifier.verify(h, signature)

def forge_signature(message, key):
  h = SHA.new(message).hexdigest()
  asn_prefix = '3021300906052b0e03021a05000414'
  desired_message = '01ff00' + asn_prefix + h + 'ff' * 80
  m = int(desired_message, 16)
  s = util.iroot(3, m)
  signature = util.int_to_bytes(s)
  return signature

if __name__ == '__main__':
  key = RSA.generate(1024, e = 3)
  public_key = key.publickey()

  message = b'hi mom'
  h = SHA.new(message)
  sha1 = h.hexdigest()
  signer = PKCS1_v1_5.new(key)
  signature = signer.sign(h)

  assert faulty_verifier(message, signature, public_key)
  assert legit_verifier(message, signature, public_key)

  forgery = forge_signature(message, public_key)

  assert faulty_verifier(message, forgery, public_key)
  assert not legit_verifier(message, forgery, public_key)

  print('Successfully forged RSA signature!')
