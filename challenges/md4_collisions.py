from utilities import hashes
from utilities import util
import binascii

# Notes
#   * Wang et. al uses 1-indexing in their paper, for reasons
#     passing understanding. We'll use 0-indexing here

def f(x, y, z): return hashes._f(x, y, z)
def g(x, y, z): return hashes._g(x, y, z)
def h(x, y, z): return hashes._h(x, y, z)

def lrot(m, s): return hashes._left_rotate(m, s)
def rrot(m, s): return hashes._right_rotate(m, s)

def generate_collision():
  m = util.random_byte_string(64) # 128 bits
  x = list(hashes.little_endian_words(m))

  state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
  a0, b0, c0, d0 = h0, h1, h2, h3 = state

  # a[1][7] = b[0][7]
  a1 = lrot(a0 + f(b0, c0, d0) + x[0], 3)
  a1 ^= (a1 ^ (b0 & (1 << 6)))
  x[0] = rrot(a1, 3) - a0 - f(b0, c0, d0)

  # d[1][7] = 0
  



  return b'a', b'b'

def pretty_print_hex(x):
  return binascii.hexlify(x).decode('utf-8')

if __name__ == '__main__':
  m1, m2 = generate_collision()
  assert m1 != m2
  h1 = hashes.MD4(m1)
  h2 = hashes.MD4(m2)
  print("m1: {}".format(pretty_print_hex(m1)))
  print("m2: {}".format(pretty_print_hex(m2)))

  print("m1 hash: {}".format(pretty_print_hex(h1)))
  print("m2 hash: {}".format(pretty_print_hex(h2)))

  assert h1 == h2
  print('Success!')
