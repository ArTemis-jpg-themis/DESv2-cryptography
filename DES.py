import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64

# Define the encryption function
def encrypt_des(plaintext, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.DES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext, iv

# Define the decryption function
def decrypt_des(ciphertext, key, iv):
    cipher = Cipher(algorithms.DES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

# Set up the Streamlit app
st.title("DES Encryption and Decryption")

# Get the plaintext message from the user
plaintext = st.text_input("Enter a message to encrypt: ", "")

# Get the DES key and initialization vector from the user
key = st.text_input("Enter a DES key (8 bytes): ", "")
key = key.encode()
iv = st.text_input("Enter an initialization vector (8 bytes): ", "")
iv = iv.encode()

# Check if the plaintext message and DES key are not empty
if plaintext and key and iv:
    # Encrypt the plaintext message
    ciphertext, iv = encrypt_des(plaintext.encode(), key, iv)

    # Display the encrypted message and the initialization vector
    st.write("Encrypted message: ", base64.b64encode(ciphertext).decode())
    st.write("Initialization vector: ", base64.b64encode(iv).decode())

    # Get the ciphertext message from the user
    ciphertext = st.text_input("Enter a ciphertext message to decrypt: ", "")
    ciphertext = base64.b64decode(ciphertext)

    # Check if the ciphertext message is not empty
    if ciphertext:
        # Decrypt the ciphertext message
        decrypted_text = decrypt_des(ciphertext, key, iv)

        # Display the decrypted message
        st.write("Decrypted message: ", decrypted_text.decode())
