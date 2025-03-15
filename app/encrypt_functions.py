import os
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from dotenv import load_dotenv
load_dotenv()

TOTP_SECRET_KEY = base64.b64decode(os.getenv("TOTP_SECRET_KEY").encode('utf-8'))


def generate_encryption_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=100_000)

def encrypt_data_aes_gcm(data, key):
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, iv, tag

def decrypt_data_aes_gcm(ciphertext, key, iv, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)

def decrypt_totp_secret(totp_secret_encrypted):
    totp_full = base64.b64decode(totp_secret_encrypted)
    totp_iv = totp_full[:12]
    totp_tag = totp_full[12:28]
    totp_salt = totp_full[28:44]
    totp_secret_encrypted = totp_full[44:]
    totp_key = generate_encryption_key(TOTP_SECRET_KEY, totp_salt)
    return decrypt_data_aes_gcm(totp_secret_encrypted, totp_key, totp_iv, totp_tag).decode('utf-8')
