from utilities import util
import binascii
import os

# Challenge 50

original = b"alert('MZA who was that?');\n"
new = b"alert('Ayo, the Wu is back!')\n//"
the_hash = b'296b8d7cb78a243dda4d0a61d33bbdd1'
key = b'YELLOW SUBMARINE'

if __name__ == '__main__':
  assert binascii.hexlify(util.cbc_mac(original, key)) == the_hash

  my_mac = util.cbc_mac(new, key)
  forged_message = util.padding(new, 16) + util.xor(my_mac, original[:16]) + original[16:]

  assert binascii.hexlify(util.cbc_mac(forged_message, key)) == the_hash

  html = b'<script>\n' + forged_message + b'</script>'
  with open('/tmp/test.html', 'wb') as f:
    f.write(html)
  os.system('open /tmp/test.html')
  print('Success!')
