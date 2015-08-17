import base64
import binascii
from utilities import util, analysis

# Challenge 4

def break_single_char_xor(hexc):
  c = binascii.unhexlify(hexc)
  min_score = 100
  answer = ''
  for k in range(256):
    x = util.single_char_xor(c, k)
    s = analysis.frequency_metric(x)
    if s < min_score:
      min_score = s
      answer = x
  return (answer, min_score)

if __name__ == '__main__':
  with open('../data/4.txt') as f:
    final_answer = ''
    min_min_score = 100
    hexc = f.readline().rstrip()
    while hexc != '\n' and hexc != '':
      (answer, min_score) = break_single_char_xor(hexc)
      if min_score < min_min_score:
        final_answer = answer
        min_min_score = min_score
      hexc = f.readline().rstrip()

    print(final_answer)

