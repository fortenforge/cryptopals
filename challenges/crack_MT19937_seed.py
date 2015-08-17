import MT19937_PRNG
import time
import random

# Challenge 22

MIN_TIME = 40
MAX_TIME = 1000

def generate_number():
  time.sleep(random.randint(MIN_TIME, MAX_TIME))
  seed = int(time.time())
  print("The true seed was {}".format(seed))
  MT19937_PRNG.initialize_generator(seed)
  time.sleep(random.randint(MIN_TIME, MAX_TIME))
  return MT19937_PRNG.extract_number()


if __name__ == '__main__':
  output = generate_number()
  now = int(time.time())
  for i in range(now - MAX_TIME, now - MIN_TIME):
    MT19937_PRNG.initialize_generator(i)
    if output == MT19937_PRNG.extract_number():
      print("I think the seed was {}".format(i))  
      break

