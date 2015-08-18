class Twister:
  '''A MT19937 PRNG'''
  STATE_SIZE  = 624
  MAGIC_NUMS  = [1812433253, 2636928640, 4022730752, 2567483615]
  SHIFT_SIZES = [11, 7, 15, 18]

  # Create a length Twister.STATE_SIZE array to store the state of the generator
  def __init__(self):
    self.MT = [0]*Twister.STATE_SIZE
    self.index = 0

  # Initialize the generator from a seed
  def initialize_generator(self, seed):
    self.index = 0
    self.MT[0] = seed
    for i in range(1, Twister.STATE_SIZE):
      self.MT[i] = (((self.MT[i-1] >> 30) ^ self.MT[i-1]) * Twister.MAGIC_NUMS[0]+ i) & ((1 << 32) - 1)

  # Extract a tempered pseudorandom number based on the index-th value,
  # calling generate_numbers() every Twister.STATE_SIZE numbers
  def extract_number(self):
    if self.index == 0:
      self.generate_numbers()

    y = self.MT[self.index]
    y = y ^  (y >> Twister.SHIFT_SIZES[0])
    y = y ^ ((y << Twister.SHIFT_SIZES[1]) & Twister.MAGIC_NUMS[1])
    y = y ^ ((y << Twister.SHIFT_SIZES[2]) & Twister.MAGIC_NUMS[2])
    y = y ^  (y >> Twister.SHIFT_SIZES[3])

    self.index = (self.index + 1) % Twister.STATE_SIZE
    return y

  # Generate an array of Twister.STATE_SIZE untempered numbers
  def generate_numbers(self):
    for i in range(Twister.STATE_SIZE):
      y = (self.MT[i] & 0x80000000) + (self.MT[(i+1) % Twister.STATE_SIZE] & 0x7fffffff)
      self.MT[i] = self.MT[(i + 397) % Twister.STATE_SIZE] ^ (y >> 1)
      if (y % 2) != 0:
        self.MT[i] = self.MT[i] ^ Twister.MAGIC_NUMS[3]

