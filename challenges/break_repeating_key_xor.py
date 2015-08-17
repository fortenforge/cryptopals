import base64
import binascii
from utilities import util, analysis

# Challenge 6

def break_single_char_xor(c):
  min_score = 100
  answer = b''
  key = b''
  for k in range(256):
    x = util.single_char_xor(c, k)
    s = analysis.frequency_metric(x)
    if s < min_score:
      min_score = s
      answer = x
      key = k
  return (answer, bytes([key]))

def find_keysize(c):
  min_score = 10000000
  keysize_final = 1
  for keysize in range(2,34):

    average_distance = 0
    for i in range(4):
      for j in range(i+1,4):
        average_distance += analysis.hamming_distance(c[keysize*i:keysize*(i+1)], c[keysize*j:keysize*(j+1)])
    average_distance /= 6

    score = average_distance/keysize
    if score < min_score:
      min_score = score
      keysize_final = keysize
  return keysize_final

def break_repeating_key_xor(ciphertext):
  keysize = find_keysize(ciphertext)
  trans_ciphertext = [b'']*keysize

  for k in range(len(ciphertext)):
    trans_ciphertext[k%keysize] += ciphertext[k:k+1]

  trans_plaintext = [b'']*keysize
  key = b''
  i = 0
  for col_ciphertext in trans_ciphertext:
    (col_plaintext, k) = break_single_char_xor(col_ciphertext)
    key += k
    trans_plaintext[i] = col_plaintext
    i += 1

  plaintext = b''
  for i in range(len(ciphertext)):
    row_index = i%keysize
    col_index = i//keysize
    plaintext += trans_plaintext[row_index][col_index:col_index+1]

  return (key, plaintext.decode('utf-8'))

if __name__ == '__main__':
  ciphertext = util.open_base64_file('../data/6.txt')
  (key, plaintext) = break_repeating_key_xor(ciphertext)
  print('key: ' + key.decode('utf-8'))
  print(plaintext)

