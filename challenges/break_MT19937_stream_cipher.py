from utilities import twister, util
import time
import random

# Challenge 24

def encrypt(plaintext, seed):
  generator = twister.Twister()
  generator.initialize_generator(seed)
  ciphertext = bytes([p ^ (generator.extract_number() % 256) for p in plaintext])
  return ciphertext

def decrypt(ciphertext, seed):
  return encrypt(ciphertext, seed)

def encrypt_known_plaintext(seed, known_plaintext):
  prefix = util.random_byte_string(random.randint(5, 10))
  return encrypt(prefix + known_plaintext, seed)

def break_small_key():
  known_plaintext = b'A'*14
  true_seed = 33342
  ciphertext = encrypt_known_plaintext(true_seed, known_plaintext)
  for i in range((1 << 16) - 1):
    test_plaintext = decrypt(ciphertext, i)
    if test_plaintext[-len(known_plaintext):] == known_plaintext:
      print(i)
      print(true_seed == i)
      break

def break_password_reset():
  known_plaintext = b' is your password reset token'
  true_seed = int(time.time())
  ciphertext = encrypt_known_plaintext(true_seed, known_plaintext)
  curr_time = int(time.time())
  secs_back = 100

  for i in range(curr_time - secs_back, curr_time + 1):
    test_plaintext = decrypt(ciphertext, i)
    if test_plaintext[-len(known_plaintext):] == known_plaintext:
      return True
  return False

if __name__ == '__main__':
  print(break_password_reset())

