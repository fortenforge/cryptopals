import base64
import binascii
from utilities import util, analysis

# Challenge 3

if __name__ == '__main__':
  c = binascii.unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
  min_score = 100
  answer = ''
  for k in range(256):
      x = util.single_char_xor(c, k)
      s = analysis.frequency_metric(x)
      if s < min_score:
          min_score = s
          answer = x
  print(answer)

