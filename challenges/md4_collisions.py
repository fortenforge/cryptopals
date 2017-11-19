from utilities import hashes
from utilities import util
from Crypto.Hash import MD4
import binascii
import struct
import time

# Notes
#   * Wang et. al uses 1-indexing in their paper, for reasons
#     passing understanding. We'll use 0-indexing here.
#   * After about 2 million tries, this script produced a brand new
#     md4 collision:
#     m1 = a6af943ce36f0cf4adcb12bef7f0dc1f526dd914bd3da3cafde14467ab129e640b4c41819915cb43db752155ae4b895fc71b9b0d384d06ef3118bbc643ae6384
#     m2 = a6af943ce36f0c74adcb122ef7f0dc1f526dd914bd3da3cafde14467ab129e640b4c41819915cb43db752155ae4b895fc71b9a0d384d06ef3118bbc643ae6384
#     md4_hash = 6725aa416acc1e6adcb64c41f0f60694
#   * I've implemented all but 19 of the "sufficient" constraints according to
#     Wang. Later researchers have shown that Wang's conditions are not entirely
#     sufficient (https://eprint.iacr.org/2005/151.pdf). I have also included
#     one (out of 2) additional constraint from this paper (marked below).
#   * There are then a total of 19 + 1 = 20 unsatisfied constraints. This implies
#     2^20 = around 1 million tries on expectation are required to find
#     a collision. This seems to be borne out by experimental results.

count = 0

def f(x, y, z): return hashes._f(x, y, z)
def g(x, y, z): return hashes._g(x, y, z)
def h(x, y, z): return hashes._h(x, y, z)

def lrot(m, s): return hashes._left_rotate(m, s)
def rrot(m, s): return hashes._right_rotate(m, s)

# helper methods to adjust the state variables
# to satisfy Wang's constraints
def correct_bit_equal(u, v, i):
  b = u
  u ^= ((u ^ v) & (1 << i))
  # print('EQU {} --> {} ({})'.format(b, u, 'Changed' if b != u else 'Same'))
  return u

def correct_bit_zero(u, i):
  b = u
  u &= ~(1 << i)
  # print('ZER {} --> {} ({})'.format(b, u, 'Changed' if b != u else 'Same'))
  return u

def correct_bit_one(u, i):
  b = u
  u |= (1 << i)
  # print('ONE {} --> {} ({})'.format(b, u, 'Changed' if b != u else 'Same'))
  return u

def undo_little_endian_words(x):
  m = b''
  for xi in x:
    m += struct.pack('<I', xi)
  return m

# enforce first-round constraints
def do_op(state, j, i, s, x, constraints):
  # perform the MD4 operation
  v = lrot(state[j%4] +
          f(state[(j+1)%4], state[(j+2)%4], state[(j+3)%4]) +
          x[i], s)

  # correct the bits according to the constraints
  for constraint in constraints:
    if   constraint[0] == 'equ':
      v = correct_bit_equal(v, state[(j+1)%4], constraint[1])
    elif constraint[0] == 'zer':
      v = correct_bit_zero(v, constraint[1])
    elif constraint[0] == 'one':
      v = correct_bit_one(v, constraint[1])

  # compute the correct message word using algebra
  x[i] = rrot(v, s) - state[j%4] - f(state[(j+1)%4], state[(j+2)%4], state[(j+3)%4])
  x[i] = x[i] % (1 << 32)

  # update the state
  state[j%4] = v
  return

# When given a weak message (i.e. a message that satisfies all or most of Wang's
# constraints, this function flips a few bits and returns a potentially
# colliding message
def create_colliding_message(m):
  x = list(hashes.little_endian_words(m))
  x[1] = (x[1] + (1 << 31)) % (1 << 32)
  x[2] = (x[2] + ((1 << 31) - (1 << 28))) % (1 << 32)
  x[12] = (x[12] - (1 << 16)) % (1 << 32)
  return undo_little_endian_words(x)

# helper methods to check Wang's constraints
def check_bit_equal(u, v, i):
  assert ((u ^ v) & (1 << i)) == 0

def check_bit_zero(u, i):
  assert (u & (1 << i)) == 0

def check_bit_one(u, i):
  assert (u & (1 << i)) != 0

# This function checks that a given message satisfies all the programmed
# constraints (for debugging purposes)
def constraints_checker(x, constraints, constraints2):
  state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

  w = [0, 3, 2, 1] * 4
  shifts = [3, 7, 11, 19] * 4

  # first-round constraints checking
  for i in range(16):
    state[w[i]] = hashes._f1(state[w[i]],
                      state[(w[i]+1)%4],
                      state[(w[i]+2)%4],
                      state[(w[i]+3)%4],
                      i,
                      shifts[i],
                      x)
    constraint = constraints[i]
    for c in constraint:
      if   c[0] == 'equ':
        check_bit_equal(state[w[i]], state[w[(i+3)%16]], c[1])
      elif c[0] == 'zer':
        check_bit_zero(state[w[i]], c[1])
      elif c[0] == 'one':
        check_bit_one(state[w[i]], c[1])
    # print('pass {}'.format(i))

  # second-round constraints checking
  state[0] = hashes._f2(state[0], state[1], state[2], state[3], 0, 3, x)
  for c in constraints2[0]:
    if   c[0] == 'equ':
      check_bit_equal(state[0], state[c[2]], c[1])
    elif c[0] == 'zer':
      check_bit_zero(state[0], c[1])
    elif c[0] == 'one':
      check_bit_one(state[0], c[1])

  state[3] = hashes._f2(state[3], state[0], state[1], state[2], 4, 5, x)
  for c in constraints2[1]:
    if   c[0] == 'equ':
      check_bit_equal(state[3], state[c[2]], c[1])
    elif c[0] == 'zer':
      check_bit_zero(state[3], c[1])
    elif c[0] == 'one':
      check_bit_one(state[3], c[1])

def generate_probable_collision():
  # generate random initial message
  m = util.random_byte_string(64) # 128 bits
  x = list(hashes.little_endian_words(m))

  initial_state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
  state = [q for q in initial_state]

  # first round constraints
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
      ['one', 21],
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
      ['equ', 31]  # extra constraint from Naito, et al.
    ],
  ]

  shifts = [3, 7, 11, 19] * 4
  starts = [0, 3, 2, 1] * 4

  for i in range(16):
    do_op(state, starts[i], i, shifts[i], x, constraints[i])

  # second-round constraints
  constraints2 = [
    [
      ['equ', 18, 2],
      ['one', 25],
      ['zer', 26],
      ['one', 28],
      ['one', 31]
    ],
    [
      # ['equ', 18, 0], # for some reason these 3 constraints aren't being
      # ['equ', 25, 1], # reliably satisfied using Wang's multi-step technique
      # ['equ', 26, 1],
      ['equ', 28, 1],
      ['equ', 31, 1]
    ]
  ]

  # a5 constraint

  # compute a5
  a5 = hashes._f2(state[0], state[1], state[2], state[3], 0, 3, x)
  q = a5
  for constraint in constraints2[0]:
    # modify a5 to meet the constraints
    if   constraint[0] == 'equ':
      a5 ^= ((a5 ^ state[constraint[2]]) & (1 << constraint[1]))
      # print('EQU {} --> {} ({})'.format(q, a5, 'Changed' if q != a5 else 'Same'))

    elif constraint[0] == 'zer':
      a5 &= ~(1 << constraint[1])
      # print('ZER {} --> {} ({})'.format(q, a5, 'Changed' if q != a5 else 'Same'))

    elif constraint[0] == 'one':
      a5 |= (1 << constraint[1])
      # print('ONE {} --> {} ({})'.format(q, a5, 'Changed' if q != a5 else 'Same'))

  # modify x[0] to result in our new a5
  q = (rrot(a5, 3) - state[0] - g(state[1], state[2], state[3]) - 0x5a827999) % (1 << 32)
  # print('AAA {} --> {} ({})'.format(x[0], q, 'Changed' if q != x[0] else 'Same'))

  # do the multi-step corrections
  a0, b0, c0, d0 = initial_state[0], initial_state[1], initial_state[2], initial_state[3]
  a1prime = hashes._f1(a0,b0,c0,d0, 0, 3, [q])
  a1 = hashes._f1(a0,b0,c0,d0, 0, 3, x)
  d1 = hashes._f1(d0,a1,b0,c0, 1, 7, x)
  x[0] = q
  q = x[1]
  x[1] = (rrot(d1,  7) - d0 - f(a1prime, b0, c0)) % (1 << 32)
  # print('BBB {} --> {} ({})'.format(q, x[1], 'Changed' if q != x[1] else 'Same'))
  c1 = hashes._f1(c0,d1,a1,b0, 2, 11, x)
  x[2] = (rrot(c1, 11) - c0 - f(d1, a1prime, b0)) % (1 << 32)
  b1 = hashes._f1(b0,c1,d1,a1, 3, 19, x)
  x[3] = (rrot(b1, 19) - b0 - f(c1, d1, a1prime)) % (1 << 32)
  a2 = hashes._f1(a1,b1,c1,d1, 4, 3, x)
  x[4] = (rrot(a2,  3) - a1prime - f(b1, c1, d1)) % (1 << 32)

  state[0] = a5

  # d5 constraint

  # compute d5
  d5 = hashes._f2(state[3], state[0], state[1], state[2], 4, 5, x)

  for constraint in constraints2[1]:
    # modify d5 to meet the constraints
    if   constraint[0] == 'equ':
      d5 ^= ((d5 ^ state[constraint[2]]) & (1 << constraint[1]))
    elif constraint[0] == 'zer':
      d5 &= ~(1 << constraint[1])
    elif constraint[0] == 'one':
      d5 |= (1 << constraint[1])

  # modify x[4] to result in our new d5
  q = (rrot(d5, 5) - state[3] - g(state[0], state[1], state[2])- 0x5a827999) % (1 << 32)

  # do the multi-step corrections
  a, b, c, d = initial_state[0], initial_state[1], initial_state[2], initial_state[3]
  a = hashes._f1(a,b,c,d, 0, 3, x)
  d = hashes._f1(d,a,b,c, 1, 7, x)
  c = hashes._f1(c,d,a,b, 2,11, x)
  b = hashes._f1(b,c,d,a, 3,19, x)

  a2prime = hashes._f1(a,b,c,d, 4, 3, [q] * 5)
  a2 = hashes._f1(a,b,c,d, 4, 3, x)
  d2 = hashes._f1(d,a2,b,c, 5, 7, x)
  x[4] = q
  q = x[5]
  x[5] = (rrot(d2,  7) - d - f(a2prime, b, c)) % (1 << 32)
  # print('BBB {} --> {} ({})'.format(q, x[1], 'Changed' if q != x[1] else 'Same'))
  c2 = hashes._f1(c,d2,a2,b, 6, 11, x)
  x[6] = (rrot(c2, 11) - c - f(d2, a2prime, b)) % (1 << 32)
  b2 = hashes._f1(b,c2,d2,a2, 7, 19, x)
  x[7] = (rrot(b2, 19) - b - f(c2, d2, a2prime)) % (1 << 32)
  a3 = hashes._f1(a2,b2,c2,d2, 8, 3, x)
  x[8] = (rrot(a3,  3) - a2prime - f(b2, c2, d2)) % (1 << 32)

  # confirm that all our constraints are satisfied
  # constraints_checker(x, constraints, constraints2)

  m = undo_little_endian_words(x)
  mprime = create_colliding_message(m)

  if MD4.new(data=m).digest() == MD4.new(data=mprime).digest():
    return m, mprime
  return None, None

def generate_collision():
  while True:
    ma, mb = generate_probable_collision()
    if ma:
      break
    global count
    count += 1
    if count % 100 == 0:
      print(count)
  return ma, mb

def pretty_print_hex(x):
  return binascii.hexlify(x).decode('utf-8')

if __name__ == '__main__':
  start_time = time.time()
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
  print("--- %s seconds ---" % (time.time() - start_time))
