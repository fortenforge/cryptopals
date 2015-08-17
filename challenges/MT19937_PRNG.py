# Challenge 21

# Create a length 624 array to store the state of the generator
MT = [0]*624
index = 0

# Initialize the generator from a seed
def initialize_generator(seed):
  global index
  index = 0
  MT[0] = seed
  for i in range(1, 624):
    MT[i] = (((MT[i-1] >> 30) ^ MT[i-1]) * 1812433253 + i) & ((1 << 32) - 1)

# Extract a tempered pseudorandom number based on the index-th value,
# calling generate_numbers() every 624 numbers
def extract_number():
  global index
  if index == 0:
    generate_numbers()

  y = MT[index]
  y = y ^ (y >> 11)
  y = y ^ ((y << 7) & 2636928640)
  y = y ^ ((y << 15) & 4022730752)
  y = y ^ (y >> 18)

  index = (index + 1) % 624
  return y

# Generate an array of 624 untempered numbers
def generate_numbers():
  for i in range(624):
    y = (MT[i] & 0x80000000) + (MT[(i+1) % 624] & 0x7fffffff)
    MT[i] = MT[(i + 397) % 624] ^ (y >> 1)
    if (y % 2) != 0:
      MT[i] = MT[i] ^ 2567483615


if __name__ == '__main__':
  initialize_generator(1)
  for i in range(10):
    print(extract_number()) 

