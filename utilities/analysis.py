import base64
import binascii
import random
from Crypto.Cipher import AES

NUM_LETTERS = 26
LARGE_SCORE = 100

def frequency_metric(p):
  frequencies = []
  for i in range(NUM_LETTERS):
    frequencies.append(0)
  for pc in p:
    n = pc - ord('a')
    if 0 <= n < NUM_LETTERS:
      frequencies[pc - ord('a')] += 1
    elif chr(pc) == ' ':
      frequencies[-2] += 1
    else:
      frequencies[-1] += 1
  if sum(frequencies) == 0:
    return LARGE_SCORE
  english = [0.0655, 0.0127, 0.0227, 0.0335, 0.1022, 0.0197, 0.0164, 0.0486, 0.0573, 0.0011, 0.0057, 0.0336, 0.0202, 0.0570, 0.0620, 0.0150, 0.0009, 0.0497, 0.0533, 0.0751, 0.0230, 0.0079, 0.0169, 0.0015, 0.0147, 0.0006, 0.1832, 0.0]
  #english = [8.12, 1.49, 2.71, 4.32, 12.02, 2.3, 2.03, 5.92, 7.31, 0.1, 0.69, 3.98, 2.61, 6.95, 7.68, 1.82, 0.11, 6.02, 6.28, 9.1, 2.88, 1.11, 2.09, 0.17, 2.11, 0.07]
  return sum([(m/sum(frequencies) - n/sum(english))**2 for (m,n) in zip(frequencies,english)])

def detect_ECB_mode(ciphertext):
  blocks = set()
  for i in range(len(ciphertext)//16):
    block = ciphertext[16*i:16*(i+1)]
    if block in blocks:
      return True
    blocks.add(block)
  return False

def count_ones_in_byte(x):
  if x == 0:
    return 0
  return (x % 2)+ count_ones_in_byte(x//2)

def hamming_distance_chars(char_a, char_b):
  x = char_a^char_b
  return count_ones_in_byte(x)

def hamming_distance(a, b):
  distance = 0
  for i in range(len(a)):
    distance += hamming_distance_chars(a[i],b[i])
  return distance
