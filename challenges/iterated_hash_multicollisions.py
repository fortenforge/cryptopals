from utilities import util
import binascii

# Challenge 52

STATE_LEN = 2 # 16 bits
AES_BLOCK_SIZE = 16

# merkle damgard construction using AES-128 as a compression function
def md_hash(message, state_len = STATE_LEN, H = None):
  # initial state
  h = b''.join([util.int_to_bytes((37*i + 42) % 256) for i in range(state_len)])
  if not H:
    H = h
  M = util.padding(message, AES_BLOCK_SIZE)
  for i in range(len(M)//AES_BLOCK_SIZE):
    Mi = util.get_ith_block(M, i, AES_BLOCK_SIZE)
    H = util.ecb_encrypt(Mi, util.padding(H, AES_BLOCK_SIZE))[0:state_len]
  return binascii.hexlify(H)

# finds two colliding blocks for a given initial state
def find_block_collision(h):
  for b1 in range(pow(256, STATE_LEN)):
    m1 = b1.to_bytes(STATE_LEN, 'big')
    md1 = md_hash(m1, H = h)
    for b2 in range(b1 + 1, pow(256, STATE_LEN)):
      m2 = b2.to_bytes(STATE_LEN, 'big')
      md2 = md_hash(m2, H = h)
      if md2 == md1:
        return (m1, m2, binascii.unhexlify(md1))

# generates 2^rounds colliding messages
def generate_many_collisions(rounds):
  h = b''.join([util.int_to_bytes((37*i + 42) % 256) for i in range(STATE_LEN)])
  colliding_messages = set()
  colliding_messages.add(b'')
  for i in range(rounds):
    new_set = set()
    m1, m2, h = find_block_collision(h)
    m1 = util.padding(m1, AES_BLOCK_SIZE)
    m2 = util.padding(m2, AES_BLOCK_SIZE)
    for m in colliding_messages:
      new_set.add(m + m1)
      new_set.add(m + m2)
    colliding_messages = new_set
  return colliding_messages

def md_hash_hard(m):
  return md_hash(m, state_len = STATE_LEN + 1)

def composed_hash(m):
  h1 = binascii.unhexlify(md_hash(m))
  h2 = binascii.unhexlify(md_hash_hard(m))
  return binascii.hexlify(h1 + h2)

if __name__ == '__main__':
  print('Part 1: Generating 16 colliding messages:')
  colliding_messages = generate_many_collisions(4)
  for m in colliding_messages:
    print('{}\t{}'.format(binascii.hexlify(m), md_hash(m)))
  print('Success!\n')

  print('Part 2: Generating two colliding messages:')
  colliding_messages = generate_many_collisions(22)
  hash_dict = {}
  for m in colliding_messages:
    h = md_hash_hard(m)
    if h in hash_dict:
      m1 = m
      m2 = hash_dict[h]
      break
    else:
      hash_dict[h] = m
  assert m1 != m2
  assert composed_hash(m1) == composed_hash(m2)
  print('m1: {}'.format(composed_hash(m1)))
  print('m2: {}'.format(composed_hash(m2)))
  print('Success!')
