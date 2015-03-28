import base64
import binascii
import util
import analysis

# Challenge 19/20

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


def break_repeating_key_xor(ciphertext, keysize):
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

    return (key, plaintext.decode("utf-8"))

block_size = 16
key = util.random_byte_string(block_size)
f = open('20.txt')
line = f.readline().rstrip()
clist = []
min_length = 100000
while line != '\n' and line != '':
    plaintext = base64.b64decode(line)
    ciphertext = util.ctr_encrypt(plaintext, key)
    clist.append(ciphertext)
    if len(plaintext) != len(ciphertext):
        print("hod")
    min_length = min(min_length, len(ciphertext))
    line = f.readline().rstrip()

truncs = b''
for ciphertext in clist:
    truncs += ciphertext[0:min_length]

key = break_repeating_key_xor(truncs, min_length)[0]

for ciphertext in clist:
    print(util.xor(key, ciphertext))
