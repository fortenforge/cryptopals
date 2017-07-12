from utilities import util
import binascii

# Challenge 53

STATE_LEN = 4 # 32 bits
BLOCK_SIZE = 16 # 128 bits
LEN_ENC_SIZE = 8 # 64 bits

initial_state = b''.join([util.int_to_bytes((37*i + 42) % 256) for i in range(STATE_LEN)])

# Notes
#  - Modern hash functions include the length of the message (modulo some huge
#    value) in the padding. This makes some conventional attacks a little
#    trickier.
#  - Collisions are much easier to find than second pre-images (birthday
#    paradox). Finding an expandable message requires many *collisions*.
#    Colliding with an intermediate state of a long message requires a
#    second pre-image of any of the intermediate states
#  - The dummy hash function we use here has the following properties:
#     * 32 bit state
#     * 128 bit block
#     * 64 bit length encoding
#    So, finding a second pre-image requires 2^32 operations (considered
#    infeasible in terms of programming competitions), but finding a
#    collision requires only 2^16 operations, which is comparatively trivial.
#  - If we have a long enough message, say 10000 blocks long, we can collide
#    with any of the intermediate blocks requiring only 2^32 / 10000 operations
#    which is feasible.
#  - We'll use the complete text of Arthur Conan Doyle's *The Hound of the
#    Baskervilles* as our long text. It's about 20000 blocks long.

def length_padding(message):
  length = len(message)

  # first append an 01, and then enough 0's to make the length 8 mod 16
  message = message + b'\x01'
  k = (LEN_ENC_SIZE - len(message)) % BLOCK_SIZE
  if k == 0:
    k += BLOCK_SIZE
  message = message + b'\x00' * k

  # then append the original length of the message
  message += length.to_bytes(LEN_ENC_SIZE, 'big')
  return message

# merkle damgard construction using AES-128 as a compression function
def md_hash(message):
  h = initial_state
  M = length_padding(message)
  for i in range(len(M) // BLOCK_SIZE):
    Mi = util.get_ith_block(M, i, BLOCK_SIZE)
    h = util.ecb_encrypt(Mi, util.padding(h, BLOCK_SIZE))[0:STATE_LEN]
  return binascii.hexlify(h)

# instrumneted md hash (no padding, can specify initial state)
def md_hash_instrumented(M, H = initial_state):
  for i in range(len(M) // BLOCK_SIZE):
    Mi = util.get_ith_block(M, i, BLOCK_SIZE)
    H = util.ecb_encrypt(Mi, util.padding(H, BLOCK_SIZE))[0:STATE_LEN]
  return binascii.hexlify(H)

# finds a message that hashes to any value in states.keys
# with initial state h
def find_second_preimage(h, states):
  for m in range(pow(2, STATE_LEN * 8)):
    message = m.to_bytes(BLOCK_SIZE, 'big')
    m_hash = md_hash_instrumented(message, h)
    if m_hash in states:
      return message, m_hash
  return None, None

# finds two colliding blocks for a given initial state
def find_block_collision(h):
  hash_table = {}
  for m in range(pow(2, STATE_LEN * 8)):
    message = m.to_bytes(BLOCK_SIZE, 'big')
    m_hash = md_hash_instrumented(message)
    if m_hash in hash_table:
      return (hash_table[m_hash], message, m_hash)
    hash_table[m_hash] = message
  return None, None, None

# finds two colliding blocks each with its own initial state
def find_block_collision(h1, h2):
  h1_table = {}
  h2_table = {}
  for m in range(pow(2, STATE_LEN * 8)):
    message = m.to_bytes(BLOCK_SIZE, 'big')
    m_hash1 = md_hash_instrumented(message, h1)
    m_hash2 = md_hash_instrumented(message, h2)
    if m_hash1 in h2_table:
      return (message, h2_table[m_hash1], m_hash1)
    else:
      h1_table[m_hash1] = message
    if m_hash2 in h1_table:
      return (h1_table[m_hash2], message, m_hash2)
    else:
      h2_table[m_hash2] = message
  return None, None, None

# given an initial state h, finds 2 colliding messages,
#  - one of block size 1,
#  - and one of block size 2^x + 1
# to save memory, we'll only return the last block of each message
# the preceding blocks of the second message are assumed to be all 00
def find_expandable_bit(h, x):
  dummy_block = b'\x00' * BLOCK_SIZE
  h1 = h
  h2 = h
  for i in range(1 << x):
    h2 = binascii.unhexlify(md_hash_instrumented(dummy_block, h2))
  return find_block_collision(h1, h2)

# generates an expandable message with parameter k
# the resulting data structure can generate colliding messages
# of lengths between k and k + 2^k - 1 inclusive
def generate_expandable_message(k):
  h = initial_state
  # note that this is ordered in reverse as compared to the website
  # our first block pair is between 1 and 2 rather than 1 and 2^(k - 1) + 1
  block_bits = []
  for i in range(k):
    m_short, m_long, h = find_expandable_bit(h, i)
    h = binascii.unhexlify(h)
    block_bits.append((m_short, m_long))
  return block_bits, h

# given an expandable message, use it to generate a message of length x
def generate_message_with_length(expandable, x):
  k = len(expandable)
  assert k <= x <= k + (1 << k) - 1

  bit_rep = x - k
  dummy_block = b'\x00' * BLOCK_SIZE
  m = b''
  for i in range(k):
    if bit_rep % 2:
      m += dummy_block * (1 << i) + expandable[i][1]
    else:
      m += expandable[i][0]
    bit_rep //= 2
  return m

def get_intermediate_states(message, k):
  states = {}
  h = initial_state
  for i in range(len(message) // BLOCK_SIZE):
    block = util.get_ith_block(message, i, BLOCK_SIZE)
    h = md_hash_instrumented(block, h)

    # exclude intermediate states not in our expandable message regime
    if k <= i <= k + (1 << k) - 1:
      states[h] = i
    h = binascii.unhexlify(h)
  return states

if __name__ == '__main__':
  # obtain long message
  with open('../data/53.txt', 'rb') as f:
    message = f.read()

  k = 15
  states = get_intermediate_states(message, k)
  print('done generating intermediate states')

  # generate expandable message
  expandable, h = generate_expandable_message(k)
  print('done generating expandable message')

  # find bridge block
  bridge, b_hash = find_second_preimage(h, states)
  i = states[b_hash]
  print('found bridge block')

  # construct second pre-image
  preimage = generate_message_with_length(expandable, i) + bridge + message[BLOCK_SIZE*(i+1):]

  # verification
  hash1 = md_hash(message)
  hash2 = md_hash(preimage)
  assert hash1 == hash2
  assert message != preimage
  print('Success!')
