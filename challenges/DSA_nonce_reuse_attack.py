from utilities import util

import  DSA_key_recovery as dsa
import hashlib
import binascii

# Challenge 44

y = int(('2d026f4bf30195ede3a088da85e398ef869611d0f68f07'
         '13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8'
         '5519b1c23cc3ecdc6062650462e3063bd179c2a6581519'
         'f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430'
         'f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3'
         '2971c3de5084cce04a2e147821'), 16)

def read_messages():
  with open('../data/44.txt') as f:
    l = f.readlines()
    # split into chunks of 4 lines
    messages = [l[i + 1:i + 4] for i in range(0, len(l), 4)]
    for i, message in enumerate(messages):
      s = int(message[0][3:-1])
      r = int(message[1][3:-1])
      m = int(message[2][3:-1], 16)
      messages[i] = (m, r, s)
  return messages

def identify_repeated_nonces(messages):
  # print(messages)
  for i in range(len(messages)):
    for j in range(i + 1, len(messages)):
      r1 = messages[i][1]
      r2 = messages[j][1]
      if r1 == r2:
        return messages[i], messages[j]

def calculate_nonce(m1, s1, m2, s2):
  q = dsa.q
  return ((m1 - m2) * util.modinv(s1 - s2, q)) % q

if __name__ == '__main__':
  messages = read_messages()
  (m1, r1, s1), (m2, r2, s2) = identify_repeated_nonces(messages)
  k = calculate_nonce(m1, s1, m2, s2)
  x = dsa.recover_key(m1, (r1, s1), k)

  assert pow(dsa.g, x, dsa.p) == y
  hash_x = 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'
  assert hashlib.sha1(hex(x)[2:].encode('utf-8')).hexdigest() == hash_x

  print('Successfully recovered private key!')
