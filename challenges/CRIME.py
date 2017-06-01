from utilities import util
import zlib
import random

# Challenge 51

SESSION_ID = 'TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='
alphabet = ''.join([chr(a) for a in range(128)])

def oracle(p, enc):
  post_temp = 'POST / HTTP/1.1\nHost: hapless.com\nCookie: sessionid={}\nContent-Length: {}\n{}'
  post_req = post_temp.format(SESSION_ID, len(p), p).encode('utf-8')
  post_comp = zlib.compress(post_req)
  return len(enc(post_comp))

def stream_encrypt(p):
  key = util.random_byte_string(16)
  nonce = random.randint(0, 1000000)
  return util.ctr_encrypt(p, key, nonce=nonce)

def block_encrypt(p):
  key = util.random_byte_string(16)
  iv = util.random_byte_string(16)
  return util.cbc_encrypt(p, key, iv=iv)

def crime_stream():
  plaintext = 'sessionid='
  start_length = len(plaintext)
  stop_length = len(plaintext) + len(SESSION_ID)
  while len(plaintext) < stop_length:
    min_length = stop_length * 10
    best_c = ''
    for c in alphabet:
      trial = plaintext + c
      length = oracle(trial, stream_encrypt)
      if length < min_length:
        best_c = c
        min_length = length
    if best_c == '\x00':
      # If all result in same length, try looking ahead by two
      min_length = stop_length * 10
      for c1 in alphabet:
        for c2 in alphabet:
          trial = plaintext + c1 + c2
          length = oracle(trial, stream_encrypt)
          if length < min_length:
            best_c = c1 + c2
            min_length = length
    plaintext += best_c
  return plaintext[start_length:]

def crime_block():
  plaintext = 'sessionid='
  start_length = len(plaintext)
  stop = len(SESSION_ID)
  count = 0
  while count < stop:
    cur_length = oracle(plaintext, block_encrypt)
    padding = '\x00'
    while oracle(plaintext + padding, block_encrypt) == cur_length:
      padding += chr(random.randint(0,128))
    padding = padding[1:]
    min_length = cur_length + 16
    for c in alphabet:
      if oracle(plaintext + c + padding, block_encrypt) < min_length:
        plaintext += c
        break
    if c == '\x7f':
      # If all result in same length, try looking ahead by two
      cur_length = oracle(plaintext, block_encrypt)
      padding = '\x00\x01'
      while oracle(plaintext + padding, block_encrypt) == cur_length:
        padding += chr(random.randint(0,128))
      padding = padding[2:]
      min_length = cur_length + 16
      flag = False
      for c1 in alphabet:
        for c2 in alphabet:
          if oracle(plaintext + c1 + c2 + padding, block_encrypt) < min_length:
            plaintext += c1 + c2
            count += 1
            flag = True
            break
        if flag:
          break
    count += 1
  return plaintext[start_length:]

if __name__ == '__main__':
  plaintext = crime_stream()
  print(plaintext)
  assert plaintext == SESSION_ID
  print('Success!')
  plaintext = crime_block()
  print(plaintext)
  assert plaintext == SESSION_ID
  print('Success!')
