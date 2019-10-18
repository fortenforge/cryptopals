from setuptools import setup

setup(
  name             = 'cryptopals',
  version          = '0.1.0',
  description      = '',
  author           = '',
  author_email     = '',
  packages         = [
    'utilities'
  ],
  install_requires = [
    'pycrypto == 2.6.1',
    'flask == 1.0',
    'urllib3 == 1.12'
  ]
)
