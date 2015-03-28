import base64
import util

# Challenge 18

plaintext = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
print(util.ctr_decrypt(plaintext, 'YELLOW SUBMARINE').decode("utf-8"))
