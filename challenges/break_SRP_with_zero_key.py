from utilities import util
from utilities import HMAC

import SRP as srp

# Challenge 37

def send_params_M():
  return 0

def send_hmac_M(salt, B):
  K = srp.SHA256(util.int_to_bytes(0))
  return HMAC.HMAC(srp.SHA256, K, salt)

if __name__ == '__main__':
  # Simulate Secure Remote Password
  srp.initialize_S()
  A         = srp.send_params_C()
  (salt, B) = srp.send_params_S(A)
  hmac      = srp.send_hmac_C(salt, B)
  response  = srp.verify_hmac_S(hmac)
  assert response
  print('Successfully executed SRP Protocol')

  # Break SRP with A = 0
  srp.initialize_S()
  A         = send_params_M()
  (salt, B) = srp.send_params_S(A)
  hmac      = send_hmac_M(salt, B)
  response  = srp.verify_hmac_S(hmac)
  assert response
  print('Successfully logged in without password')
