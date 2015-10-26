from flask       import Flask
from flask       import request
from time        import sleep
from utilities   import HMAC
import binascii

app = Flask(__name__)
SLEEP_TIME = 5/1000
KEY = b'bar'

@app.route('/verify')
def verify_HMAC():
  truth = HMAC.HMAC_SHA1(request.args.get('file', '').encode('utf-8'), KEY)
  given = binascii.unhexlify(request.args.get('signature', ''))
  if insecure_compare(truth, given):
    return 'Verified'
  else:
    return 'Not Verified'

def insecure_compare(first, second):
  for b1, b2 in zip(first, second):
    if b1 != b2:
      return False
    sleep(SLEEP_TIME)
  return True

if __name__ == '__main__':
  app.run(debug=True)
