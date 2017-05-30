from utilities import util

BLOCKSIZE = 16
shared_key = b'YELLOW SUBMARINE'

victim_id   = 73628
attacker_id = 23093
attack_amount = 1000000 # "1M spacebucks"

# Challenge 49

def server(m, var_iv = False):
  mac = m[-BLOCKSIZE:]
  iv = b'\x00' * BLOCKSIZE if not var_iv else m[-2*BLOCKSIZE:-BLOCKSIZE]
  message = m[:-BLOCKSIZE] if not var_iv else m[:-2*BLOCKSIZE]
  assert util.cbc_mac(message, shared_key, iv) == mac

  message = message.decode('utf-8')

  from_half = message.split('&')[0]
  from_id = int(from_half[from_half.index(';from=') + len(';from='):])

  to_half = message.split('&')[1]
  tx_list = to_half[len('tx_list='):].split(';')

  for tx in tx_list:
    to_id = int(tx.split(':')[0])
    amount = tx.split(':')[1]
    print("Moving {} spacebucks from {} to {}".format(amount, from_id, to_id))

    if to_id == attacker_id and from_id == victim_id and amount == str(attack_amount):
      print("Success!")
      return

# pretend that the client authenticates `from_id`
# so the attacker shouldn't be able to call this with anything
# other than `from_id = attacker_id`
def client(from_id, tx_list, var_iv = False, note = b""):
  message = ';from={}&tx_list='.format(from_id)
  for (to, amount) in tx_list:
    message += '{}:{};'.format(to, amount)
  message = message[:-1].encode('utf-8')
  message = note + message
  iv = util.random_byte_string(BLOCKSIZE) if var_iv else b'\x00' * BLOCKSIZE
  mac = util.cbc_mac(message, shared_key, iv)
  return message + (iv if var_iv else b'') + mac

def attacker1():
  tx_list = [(attacker_id, attack_amount)]
  message1 = client(attacker_id, tx_list, True)
  message2 = ';from={}&tx_list={}:{}'.format(victim_id, attacker_id, attack_amount).encode('utf-8')
  iv = message1[-2*BLOCKSIZE:-BLOCKSIZE]
  mac = message1[-BLOCKSIZE:]
  my_iv = util.xor(util.xor(iv, message1[0:BLOCKSIZE]), message2[0:BLOCKSIZE])
  forged_message = message2 + my_iv + mac
  server(forged_message, True)

def attacker2(m):
  message1 = util.padding(m[:-BLOCKSIZE], BLOCKSIZE)
  mac = m[-BLOCKSIZE:]

  my_tx = ';{}:{};'.format(attacker_id, attack_amount).encode('utf-8')
  my_tx = util.padding(my_tx, BLOCKSIZE)
  m2 = client(attacker_id, [(1,1)], note = util.xor(my_tx, mac))
  my_mac = m2[-BLOCKSIZE:]
  forged_message = message1 + my_tx + m2[BLOCKSIZE:-BLOCKSIZE]
  server(forged_message + my_mac)

if __name__ == '__main__':
  print("Testing server")
  server(client(7777, [(1234, 10000), (1235, 1000), (123, 100)]))

  print("\nAttack #1: Variable IV")
  attacker1()

  print("\nAttack #2: Length Extension")
  m = client(victim_id, [(1234, 10)])
  attacker2(m)
