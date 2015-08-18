from utilities import util
from Crypto.Cipher import AES
import struct

# Challenge 25

def edit(ciphertext, key, offset, newtext):
  block_size = 16
  AES_obj = AES.new(key, AES.MODE_ECB)
  nonce = nonce = struct.pack('<Q', 0)

  block_index = offset // block_size
  counter = struct.pack('<Q', block_index)
  current_block = AES_obj.encrypt(nonce + counter)

  replace_text = []

  for i in range(offset, len(newtext) + offset):
    replace_text.append(current_block[i % block_size] ^ newtext[i - offset])

    if (i+1) % 16 == 0:
      block_index += 1
      counter = struct.pack('<Q', block_index)
      current_block = AES_obj.encrypt(nonce + counter)

  return ciphertext[0:offset] + bytes(replace_text) + ciphertext[offset + len(newtext):]

if __name__ == '__main__':
  ciphertext = util.open_base64_file('../data/25.txt')
  key = 'YELLOW SUBMARINE'
  plaintext = util.ecb_decrypt(ciphertext, key)

  key = util.random_byte_string(16)
  ciphertext = util.ctr_encrypt(plaintext, key)

  guessed_plaintext = b''
  for i in range(len(ciphertext)):
    c = ciphertext[i]
    for q in range(256):
      p = bytes([q])
      g = edit(ciphertext, key, i, p)[i]
      if g == c:
        guessed_plaintext += p
        break

  print(guessed_plaintext.decode('utf-8'))

