import urllib3
import time
import binascii
import operator

# Challenge 31/32

FILE_NAME  = b'foo'
BLOCK_SIZE = 20
NUM_ITERS  = 2
URL        = 'http://localhost:5000/verify?file={}&signature={}'
HTTP       = urllib3.PoolManager()

def break_HMAC_SHA1():
  # The first request will always be slow, so we will make it before everything else
  HTTP.request('GET', URL.format(FILE_NAME, bytes([0])*BLOCK_SIZE))

  guess = bytes([0])*BLOCK_SIZE
  for i in range(BLOCK_SIZE):
    max_time = 0
    b = 0
    for c in range(256):
      guess = guess[0:i] + bytes([c]) + guess[i+1:]
      hex_guess = binascii.hexlify(guess)

      start = time.time()
      response = HTTP.request('GET', URL.format(FILE_NAME.decode('utf-8'), hex_guess.decode('utf-8')))
      end = time.time()
      time_elapsed = end - start

      # print('{} {}'.format(hex_guess, time_elapsed))

      if response.data == b'Verified':
        return 'Success'

      if time_elapsed > max_time:
        max_time = time_elapsed
        b = c
    guess = guess[0:i] + bytes([b]) + guess[i+1:]
  return 'Fail'

def break_HMAC_SHA1_averaging():
  # The first request will always be slow, so we will make it before everything else
  HTTP.request('GET', URL.format(FILE_NAME, bytes([0])*BLOCK_SIZE))

  guess = bytes([0])*BLOCK_SIZE
  for i in range(BLOCK_SIZE):
    min_times = {}

    for _ in range(NUM_ITERS):
      for c in range(256):
        guess = guess[0:i] + bytes([c]) + guess[i+1:]
        hex_guess = binascii.hexlify(guess)

        start = time.time()
        response = HTTP.request('GET', URL.format(FILE_NAME.decode('utf-8'), hex_guess.decode('utf-8')))
        end = time.time()
        t = end - start

        min_times[c] = t if not c in min_times else min(min_times[c], t)
        # print('{} {}'.format(hex_guess, t))

        if response.data == b'Verified':
          return 'Success'

    b = max(min_times.items(), key=operator.itemgetter(1))[0]
    guess = guess[0:i] + bytes([b]) + guess[i+1:]
    print(binascii.hexlify(guess))
  return 'Fail'

if __name__ == '__main__':
  print(break_HMAC_SHA1_averaging())
