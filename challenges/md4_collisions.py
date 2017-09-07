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

# helper methods to adjust the state variables
# to satisfy wang's constraints
def correct_bit_equal(u, v, i):
  u ^= (u ^ (v & (1 << i)))
  return u

def corret_bit_zero(u, i):
  u &= ~(1 << i)
  return u

def correct_bit_one(u, i):
  u |= (1 << i)
  return u

def do_op(state, j, i, s, x, constraints):
  # perform the MD4 operation
  v = lrot(state[j%4] +
          f(state[(j+1)%4], state[(j+2)%4], state[(j+3)%4]) +
          x[i], s)

  # correct the bits according to the constraints
  for constraint in constraints:
    if constraint[0] == 'equ':
      correct_bit_equal(v, state[(j+1)%4], constraint[1])
    elif constraint[0] == 'zer':
      correct_bit_zero(v, constraint[1])
    elif constriant[0] == 'one':
      correct_bit_one(v, constraint[1])

  # compute the correct message word using algebra
  x[i] = rrot(v, s) -
         state[j%4] -
         f(state[(j+1)%4], state[(j+2)%4], state[(j+3)%4])
  return


def generate_collision():
  m = util.random_byte_string(64) # 128 bits
  x = list(hashes.little_endian_words(m))

  state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

  constraints = [
    [
      ['equ', 6]
    ],
    [
      ['zer', 6],
      ['equ', 7],
      ['equ', 10]
    ],
    [
      ['one', 6],
      ['one', 7],
      ['zer', 10],
      ['equ', 25]
    ],
    [
      ['one', 6],
      ['zer', 7],
      ['zer', 10],
      ['zer', 25]
    ],
    [
      ['one', 7],
      ['one', 10],
      ['zer', 25],
      ['equ', 13]
    ],
    [
      ['zer', 13],
      ['equ', 18],
      ['equ', 19],
      ['equ', 20],
      ['equ', 21],
      ['one', 25]
    ],
    [
      ['equ', 12],
      ['zer', 13],
      ['equ', 14],
      ['zer', 18],
      ['zer', 19],
      ['one', 20],
      ['zer', 21]
    ],
    [
      ['one', 12],
      ['one', 13],
      ['zer', 14],
      ['equ', 16],
      ['zer', 18],
      ['zer', 19],
      ['zer', 20],
      ['zer', 21]
    ],
    [
      ['one', 12],
      ['one', 13],
      ['one', 14],
      ['zer', 16],
      ['zer', 18],
      ['zer', 19],
      ['zer', 20],
      ['equ', 22],
      ['equ', 21],
      ['equ', 25]
    ],
    [
      ['one', 12],
      ['one', 13],
      ['one', 14],
      ['zer', 16],
      ['zer', 19],
      ['one', 20],
      ['one', 21],
      ['zer', 22],
      ['one', 25],
      ['equ', 29]
    ],
    [
      ['one', 16],
      ['zer', 19],
      ['zer', 20],
      ['zer', 21],
      ['zer', 22],
      ['zer', 25],
      ['one', 29],
      ['equ', 31]
    ],
    [
      ['zer', 19],
      ['one', 20],
      ['one', 21],
      ['equ', 22],
      ['one', 25],
      ['zer', 29],
      ['zer', 31]
    ],
    [
      ['zer', 22],
      ['zer', 25],
      ['equ', 26],
      ['equ', 28],
      ['one', 29],
      ['zer', 31]
    ],
    [
      ['zer', 22],
      ['zer', 25],
      ['one', 26],
      ['one', 28],
      ['zer', 29],
      ['one', 31]
    ],
    [
      ['equ', 18],
      ['one', 22],
      ['one', 25],
      ['zer', 26],
      ['zer', 28],
      ['zer', 29]
    ],
    [
      ['zer', 18],
      ['equ', 25], # could also be ['one', 25]
      ['one', 26],
      ['one', 28],
      ['zer', 29],
    ],
  ]
  a0, b0, c0, d0 = h0, h1, h2, h3 = state

  # a[1][6] = b[0][6]
  a1 = lrot(a0 + f(b0, c0, d0) + x[0], 3)
  a1 ^= (a1 ^ (b0 & (1 << 6)))
  x[0] = rrot(a1, 3) - a0 - f(b0, c0, d0)

  # d[1][6] = 0
  d = _f1(d,a,b,c, 1, 7, x)
  d1 = lrot(d0 + f(a1 + b0 + c0) + x[1], 7)
  d1 &= ~(1 << 6)
  # d[1][7] = a[1][7]
  d1 ^= (d1 ^ (a1 & (1 << 7)))
  # d[1][10] = a[1][10]
  d1 ^= (d1 ^ (a1 & (1 << 10)))
  x[1] = rrot(d1, 7) - d1 - f(a1, b0, c0)







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
