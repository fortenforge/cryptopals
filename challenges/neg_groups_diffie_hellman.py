from utilities import util
from utilities import hashes

import MITM_diffie_hellman as dh

# Challenge 35

if __name__ == '__main__':
  # Simulate Diffie Hellman Protocol
  (p, g, A_A)      = dh.send_params_A()
  B_B              = dh.send_params_B(p, g, A_A)
  (ciphertext, iv) = dh.send_message_A(B_B)
  (ciphertext, iv) = dh.send_message_B(ciphertext, iv)
  print('Successfully executed DH Protocol')

  # Simulate MITM Attack on DH Protocol
  # by messing with the 'g' parameter
  (p, g, A_A)      = dh.send_params_A()
  B_B              = dh.send_params_B(p, 1, 1)
  (ciphertext, iv) = dh.send_message_A(B_B)
  (_, _)           = dh.send_message_B(ciphertext, iv)

  s = 1
  key = hashes.SHA1(util.int_to_bytes(s))
  key = util.get_ith_block(key, 0, dh.BLOCK_SIZE)
  plaintext = util.cbc_decrypt(ciphertext, key, iv)
  assert plaintext == dh.MESSAGE
  print('Successfully intercepted plaintext')

