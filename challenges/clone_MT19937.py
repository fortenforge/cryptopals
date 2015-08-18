from utilities.twister import Twister

# Challenge 23

INT_SIZE = 32
MAX_INT  = (1 << INT_SIZE) - 1

def undo_right(y, shift):
  x = 0
  y_old = 0
  i = 0

  while i*shift < INT_SIZE:
    if (i+1)*shift > INT_SIZE:
      x = x >> ((i+1)*shift - INT_SIZE)
    else:
      x = x << (INT_SIZE - (i+1)*shift)
    x = (((x ^ y) << (i*shift)) & MAX_INT) >> (INT_SIZE - shift)
    y_old = (y_old << shift) + x

    if (i+1)*shift > INT_SIZE:
      y_old = y_old >> (shift - (INT_SIZE % shift))

    i += 1

  return y_old

def undo_left(y, shift, magic):
  x = 0
  y_old = 0
  i = 0

  while (i)*shift < INT_SIZE:
    x = x << shift
    x = x & magic
    mask = ((1 << shift) - 1) << (i*shift)
    x = x ^ y
    x = x & mask & MAX_INT

    y_old = x + y_old
    i += 1

  return y_old

def untemper(y):
  y = undo_right(y, Twister.SHIFT_SIZES[3])
  y =  undo_left(y, Twister.SHIFT_SIZES[2], Twister.MAGIC_NUMS[2])
  y =  undo_left(y, Twister.SHIFT_SIZES[1], Twister.MAGIC_NUMS[1])
  y = undo_right(y, Twister.SHIFT_SIZES[0])
  return y

if __name__ == '__main__':
  state_size = Twister.STATE_SIZE
  state = [0]*state_size

  generator = Twister()
  generator.initialize_generator(0)
  for i in range(state_size):
    y = untemper(generator.extract_number())
    state[i] = y

  cloned_generator = Twister()
  cloned_generator.MT = state

  for i in range(10):
    a = generator.extract_number()
    b = cloned_generator.extract_number()
    print('{} {}'.format(a, b))

