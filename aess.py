from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

# AES encryption function
def encrypt_AES(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return ciphertext, cipher.nonce, tag

# AES decryption function
def decrypt_AES(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

def generate_key():
    key = get_random_bytes(32)
    return key



# password = input("Enter your password: ")
# key = generate_key()
# # Encrypt the hashed password
# encrypted_password, nonce, tag = encrypt_AES(password, key)
# print(nonce)
# print(tag)
# Decrypt the password (just to demonstrate)
# decrypted_password = decrypt_AES(encrypted_password, nonce, tag, key)
# print("key: ", key)
# print("Encrypted Password:", encrypted_password.hex())
# print("Decrypted Password:", decrypted_password)

