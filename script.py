import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#Encryption function
def encrypt_image(image_file, password):
    # Read the image file
    with open(image_file, 'rb') as f:
        data = f.read()

    # Generate a key from the password
    password = password.encode()
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        iterations=100000,
        length=32,
        salt=salt,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)

    # Encrypt the image data
    encrypted_data = f.encrypt(data)

    # Write the encrypted data to a new file
    encrypted_image_file = image_file + '.enc'
    with open(encrypted_image_file, 'wb') as f:
        f.write(encrypted_data)

#Decryption function
def decrypt_image(encrypted_image_file, password, new_file_name):
    # Read the encrypted image file
    with open(encrypted_image_file, 'rb') as f:
        data = f.read()

    # Generate a key from the password
    password = password.encode()
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        iterations=100000,
        length=32,
        salt=salt,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)

    # Decrypt the image data
    decrypted_data = f.decrypt(data)

    # Write the decrypted data to a new file
    with open(new_file_name, 'wb') as f:
        f.write(decrypted_data)

#Encrypt the image
encrypt_image("image.jpg", "mypassword")

#Decrypt the image to a new file called "image_decrypted.jpg"
decrypt_image("image.jpg.enc", "mypassword","image_decrypted.jpg")
