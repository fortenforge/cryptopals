# Challenge 23

def undo_right(y, shift):
  for i in range(32 / shift):
    x = (((1 << 32) - 1) - ((1 << (32 - shift)) - 1)) & y

def untemper(y):


def temper(y):
  y = y ^ (y >> 11)
  y = y ^ ((y << 7) & 2636928640)
  y = y ^ ((y << 15) & 4022730752)
  y = y ^ (y >> 18)
  return y
