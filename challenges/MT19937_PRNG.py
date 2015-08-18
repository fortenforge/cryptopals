from utilities.twister import Twister

# Challenge 21

if __name__ == '__main__':
  generator = Twister()
  generator.initialize_generator(0)

  for i in range(10):
    print(generator.extract_number())

