# The MIT License (MIT)

# Copyright (c) 2013-2015 AJ Alt

# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Code taken from https://github.com/ajalt/python-sha1

from __future__ import print_function
import struct

try:
  range = xrange
except NameError:
  pass

def state_to_hash_md4(words):
  '''convert n-byte words to bytes (little endian)'''
  hash_value = b''
  for word in words:
    hash_value += struct.pack('<I', word)
  return hash_value

def state_to_hash_sha1(words):
  '''convert n-byte words to bytes (big endian)'''
  hash_value = b''
  for word in words:
    hash_value += struct.pack('>I', word)
  return hash_value

def little_endian_bytes(words, n):
  '''convert n-byte words to bytes (little endian)'''
  for word in words:
    for _ in range(n):
      yield word & 0xff
      word >>= 8

def big_endian_bytes(words, n):
  '''convert n-byte words to bytes (big endian)'''
  for word in words:
    yield from reversed(list(little_endian_bytes([word], n)))

def little_endian_words(b):
  '''convert bytes into 4-byte words (little endian)'''
  for i in range(0, len(b), 4):
    yield from struct.unpack('<I', b[i:i+4])

def md_pad(message, length_to_bytes_function, original_byte_len = None):
  if not original_byte_len:
    original_byte_len = len(message)
  original_bit_len = original_byte_len * 8

  # append the bit '1' to the message
  message += b'\x80'

  # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
  #  is congruent to 448 (mod 512)
  message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)

  # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
  message += bytes(length_to_bytes_function(original_bit_len))
  ##### message += struct.pack(b'>Q', original_bit_len)

  return message

def make_md_hash(compress_function, state_to_hash_function, length_to_bytes_function):
  def md_hash(message, original_byte_len = None, init_state = None):
    message = md_pad(message, length_to_bytes_function, original_byte_len)
    state = init_state
    for i in range(0, len(message), 64):
      state = compress_function(message[i:i+64], state)
    return state_to_hash_function(state)

  return md_hash

def _left_rotate(n, b):
  return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff

def _right_rotate(n, b):
  return ((n >> b) | ((n & 0xffffffff) << (32 - b))) & 0xffffffff

def _f(x, y, z): return x & y | ~x & z
def _g(x, y, z): return x & y | x & z | y & z
def _h(x, y, z): return x ^ y ^ z

def _f1(a, b, c, d, k, s, X): return _left_rotate(a + _f(b, c, d) + X[k], s)
def _f2(a, b, c, d, k, s, X): return _left_rotate(a + _g(b, c, d) + X[k] + 0x5a827999, s)
def _f3(a, b, c, d, k, s, X): return _left_rotate(a + _h(b, c, d) + X[k] + 0x6ed9eba1, s)

def sha1_compress(block, state=None):

  if not state: state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
  a, b, c, d, e = h0, h1, h2, h3, h4 = state

  w = [0] * 80
  # break chunk into sixteen 32-bit big-endian words w[i]
  for j in range(16):
    w[j] = struct.unpack('>I', block[j*4:j*4 + 4])[0]
  # extend the sixteen 32-bit words into eighty 32-bit words:
  for j in range(16, 80):
    w[j] = _left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)

  for i in range(80):
    if i < 20:
      f = d ^ (b & (c ^ d)) # use alternative 1 for f from FIPS PB 180-1 to avoid ~
      k = 0x5A827999
    elif 20 <= i < 40:
      f = b ^ c ^ d
      k = 0x6ED9EBA1
    elif 40 <= i < 60:
      f = (b & c) | (b & d) | (c & d)
      k = 0x8F1BBCDC
    elif 60 <= i:
      f = b ^ c ^ d
      k = 0xCA62C1D6
    a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, a, _left_rotate(b, 30), c, d)

  return [(h0 + a) & 0xffffffff, (h1 + b) & 0xffffffff, (h2 + c) & 0xffffffff, (h3 + d) & 0xffffffff, (h4 + e) & 0xffffffff]

def md4_compress(block, state=None):

  if not state: state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
  a, b, c, d = h0, h1, h2, h3 = state

  x = list(little_endian_words(block))

  a = _f1(a,b,c,d, 0, 3, x)
  d = _f1(d,a,b,c, 1, 7, x)
  c = _f1(c,d,a,b, 2,11, x)
  b = _f1(b,c,d,a, 3,19, x)
  a = _f1(a,b,c,d, 4, 3, x)
  d = _f1(d,a,b,c, 5, 7, x)
  c = _f1(c,d,a,b, 6,11, x)
  b = _f1(b,c,d,a, 7,19, x)
  a = _f1(a,b,c,d, 8, 3, x)
  d = _f1(d,a,b,c, 9, 7, x)
  c = _f1(c,d,a,b,10,11, x)
  b = _f1(b,c,d,a,11,19, x)
  a = _f1(a,b,c,d,12, 3, x)
  d = _f1(d,a,b,c,13, 7, x)
  c = _f1(c,d,a,b,14,11, x)
  b = _f1(b,c,d,a,15,19, x)

  a = _f2(a,b,c,d, 0, 3, x)
  d = _f2(d,a,b,c, 4, 5, x)
  c = _f2(c,d,a,b, 8, 9, x)
  b = _f2(b,c,d,a,12,13, x)
  a = _f2(a,b,c,d, 1, 3, x)
  d = _f2(d,a,b,c, 5, 5, x)
  c = _f2(c,d,a,b, 9, 9, x)
  b = _f2(b,c,d,a,13,13, x)
  a = _f2(a,b,c,d, 2, 3, x)
  d = _f2(d,a,b,c, 6, 5, x)
  c = _f2(c,d,a,b,10, 9, x)
  b = _f2(b,c,d,a,14,13, x)
  a = _f2(a,b,c,d, 3, 3, x)
  d = _f2(d,a,b,c, 7, 5, x)
  c = _f2(c,d,a,b,11, 9, x)
  b = _f2(b,c,d,a,15,13, x)

  a = _f3(a,b,c,d, 0, 3, x)
  d = _f3(d,a,b,c, 8, 9, x)
  c = _f3(c,d,a,b, 4,11, x)
  b = _f3(b,c,d,a,12,15, x)
  a = _f3(a,b,c,d, 2, 3, x)
  d = _f3(d,a,b,c,10, 9, x)
  c = _f3(c,d,a,b, 6,11, x)
  b = _f3(b,c,d,a,14,15, x)
  a = _f3(a,b,c,d, 1, 3, x)
  d = _f3(d,a,b,c, 9, 9, x)
  c = _f3(c,d,a,b, 5,11, x)
  b = _f3(b,c,d,a,13,15, x)
  a = _f3(a,b,c,d, 3, 3, x)
  d = _f3(d,a,b,c,11, 9, x)
  c = _f3(c,d,a,b, 7,11, x)
  b = _f3(b,c,d,a,15,15, x)

  return [(h0 + a) & 0xffffffff, (h1 + b) & 0xffffffff, (h2 + c) & 0xffffffff, (h3 + d) & 0xffffffff]

SHA1 = make_md_hash(sha1_compress, state_to_hash_sha1, lambda length: big_endian_bytes([length], 8))
MD4  = make_md_hash(md4_compress, state_to_hash_md4, lambda length: little_endian_bytes([length], 8))
