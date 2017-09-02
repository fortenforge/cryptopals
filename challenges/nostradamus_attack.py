from utilities import util
import binascii

# Challenge 54

STATE_LEN = 4 # 32 bits
BLOCK_SIZE = 16 # 128 bits
LEN_ENC_SIZE = 8 # 64 bits

initial_state = b''.join([util.int_to_bytes((37*i + 42) % 256) for i in range(STATE_LEN)])

# Notes
#  - Hash functions are sometimes used as proof of a secret prediction. A
#    naive forgery would require a second pre-image attack.
#  - We (again) exploit the difference in difficulty between collisions
#    and second pre-images for this attack. We also exploit the ability
#    to precompute a lot of collisions.
#  - We create a funnel-like structure to hash many possible initial states
#    into one single final state
#  - The dummy hash function we use here has the following properties:
#     * 32 bit state
#     * 128 bit block
#     * 64 bit length encoding
#    Finding a second pre-image requires 2^32 operations (considered
#    infeasible in terms of programming competitions), but finding a
#    collision requires only 2^16 operations, which is comparatively trivial.
#  - If we have enough leaves in our funnel (say, 2^10 = 1024), finding
#    a collision takes only 2^22 time.
#  - We'll use the following list of spoilers below as our 'prediction'.

spoilers = b'''
* Snape kills Dumbledore
* Jon is the son of Rhaegar and Lyanna
* Rosebud was his childhood sled
* Kristin Shephard shot JR
* Verbal is Keyser Soze
* Soylent Green is people
'''

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

# instrumented md hash (no padding, can specify initial state)
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
    m_hash = md_hash_instrumented(message, binascii.unhexlify(h))
    if binascii.unhexlify(m_hash) in states:
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

# generates a funnel (binary tree) with depth k
def generate_funnel(k):
  # the structure of the funnel will be two lists of length k
  # the ith element of the lists will be a list of length 2^(k - i)
  # the jth element of that list will be either the hash state or the data
  # depending on the list
  funnel_data = []
  funnel_hash = []

  # the initial states will be the 32 bit encodings
  # of the numbers 0 to 2^k - 1
  funnel_hash.append([])
  for i in range(1 << k):
    funnel_hash[0].append(i.to_bytes(STATE_LEN, 'big'))

  for i in range(k):
    funnel_data.append([])
    funnel_hash.append([])
    for j in range(1 << (k - i - 1)):
      init_state0 = funnel_hash[i][j*2]
      init_state1 = funnel_hash[i][j*2 + 1]

      d0, d1, h = find_block_collision(init_state0, init_state1)
      assert md_hash_instrumented(d0, init_state0) == md_hash_instrumented(d1, init_state1)
      funnel_data[i].append(d0)
      funnel_data[i].append(d1)
      funnel_hash[i + 1].append(binascii.unhexlify(h))
  return funnel_data, funnel_hash


if __name__ == '__main__':
  # generate the funnel
  k = 10
  funnel_data, funnel_hash = generate_funnel(k)

  # let's say our spoilers fit inside 11 blocks
  spoiler_blocks = 11
  message_length = (spoiler_blocks + 1 + k) * BLOCK_SIZE
  dummy_message = b'\x00' * message_length
  padded_message = length_padding(dummy_message)
  padding_block = padded_message[message_length:]

  # generate prediction hash
  h_pred = md_hash_instrumented(padding_block, funnel_hash[k][0])
  print('Hash of prediction: {}'.format(h_pred.decode('utf-8')))

  print('... time passes ...')

  # construct spoiler message
  spoiler_message = spoilers + b' ' * (BLOCK_SIZE - (len(spoilers) % BLOCK_SIZE))
  h_spoiler = md_hash_instrumented(spoiler_message, initial_state)
  glue, h_funnel_leaf = find_second_preimage(h_spoiler, funnel_hash[0])

  funnel_index = int(h_funnel_leaf, 16)
  suffix = b''

  for i in range(k):
    suffix += funnel_data[i][funnel_index]
    funnel_index >>= 1

  final_message = spoiler_message + glue + suffix
  print('Prediction:')
  print(final_message)

  message_hash = md_hash(final_message)
  print('Message hash: {}'.format(message_hash.decode('utf-8')))
  assert message_hash == h_pred
  print('Success!')
