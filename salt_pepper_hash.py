import random
import string
import hashlib

def hash_password(password):
  hashed_password = hashlib.sha512((password).encode()).hexdigest()
  return hashed_password
  
def generate_salt(length=16):
    # Generate a random salt of specified length
    salt_characters = string.ascii_letters + string.digits
    salt = ''.join(random.choice(salt_characters) for _ in range(length))
    return salt

def salted_pepper_password(username, password, salt):
    # Hard-coded PEPPER
    pepper = 'your_secret_pepper_here'
    embeded_password = salt + username+ password + pepper
    return embeded_password



