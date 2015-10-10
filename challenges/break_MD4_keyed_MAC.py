from utilities import hashes, util
import struct

# Challenge 30

def construct_new_MAC(known_message, MAC, message_suffix, key_length = 16):
  NUM_REGS = 4
  original_byte_len = key_length + len(known_message)
  original_bit_len = original_byte_len * 8

  init_regs = [struct.unpack('<I', util.get_ith_block(MAC, i, 4))[0] for i in range(NUM_REGS)]

  glue_padding = b'\x80' + b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64) + struct.pack(b'<Q', original_bit_len)
  new_message = known_message + glue_padding + message_suffix

  return new_message, hashes.MD4(message_suffix, original_byte_len = key_length + len(new_message), init_state = init_regs)

def verify_message(key, message, MAC):
  return hashes.MD4(key + message) == MAC

if __name__ == '__main__':
  key = util.random_word().encode('utf-8')
  known_message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
  MAC = hashes.MD4(key + known_message)

  message_suffix = b';admin=true'

  for key_length in range(1, 20):
    new_message, new_MAC = construct_new_MAC(known_message, MAC, message_suffix, key_length = key_length)
    if verify_message(key, new_message, new_MAC):
      break

  print(new_message)
  print(new_MAC)
  print(verify_message(key, new_message, new_MAC))
