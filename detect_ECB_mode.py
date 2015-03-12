import base64
import binascii
import analysis

# Challenge 8

f = open('8.txt')
line = f.readline().rstrip()
while line != '\n' and line != '':
    ciphertext = binascii.unhexlify(line)
    line = f.readline().rstrip()
    if(analysis.detect_ECB_mode(ciphertext)):
        print(line)
