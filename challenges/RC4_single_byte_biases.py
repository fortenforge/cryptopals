from Crypto.Cipher import ARC4 as RC4
from utilities import util
import base64
import multiprocessing

cookie = base64.b64decode('QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F')

def rc4_oracle(prefix):
  key = util.random_byte_string(40)
  cipher = RC4.new(key)
  return cipher.encrypt(prefix + cookie)

def do_stuff(x):
  bias_map = {i:0 for i in range(256)}
  for i in range(1 << 19):
    ciphertext = rc4_oracle(b'A' * 15)
    bias_map[ciphertext[16]] += 1
  return bias_map

def break_rc4():
  pool = multiprocessing.Pool(8)
  x = pool.map(do_stuff, range(0,8))
  bias_map = {i:0 for i in range(256)}
  for m in x:
    for b in m:
      bias_map[b] += m[b]
  max_byte = max(bias_map, key=bias_map.get)
  print(bias_map)
  return max_byte

if __name__ == '__main__':
  print(break_rc4())
