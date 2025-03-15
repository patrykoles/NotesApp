from datetime import datetime, timedelta
import math
import pyotp
import qrcode
from Crypto.PublicKey import RSA
from passlib.hash import sha256_crypt
from io import BytesIO
import time
import random

def hash_password(password):
    hashed_password = sha256_crypt.hash(password)
    return hashed_password

def verify_password(stored_password, provided_password):
    is_valid = sha256_crypt.verify(provided_password, stored_password)
    return is_valid

def generate_totp_secret():
    return pyotp.random_base32()

def verify_totp(secret, code):
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key_text = key.export_key()
    public_key_text = key.publickey().export_key()
    return private_key_text, public_key_text

def calculate_entropy(password):
    lower_case = "abcdefghijklmnopqrstuvwxyz"
    upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    special_characters = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"

    character_set = ""
    if any(c in lower_case for c in password):
        character_set += lower_case
    if any(c in upper_case for c in password):
        character_set += upper_case
    if any(c in digits for c in password):
        character_set += digits
    if any(c in special_characters for c in password):
        character_set += special_characters

    R = len(character_set)
    L = len(password)
    
    entropy = math.log2(R)*L
    return entropy

def password_strength(password):
    entropy = calculate_entropy(password)
    
    if entropy < 60:
        return "Weak"
    elif entropy < 100:
        return "Medium"
    else:
        return "Strong"

def generate_totp_qr_code(totp_secret, username):
    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(name=username, issuer_name="NotesApp")
    img = qrcode.make(uri)
    img_byte_arr = BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr.seek(0)
    return img_byte_arr

def is_address_locked(last_failed_login, failed_login_attempts, time, no_attepmts):
    lock_time = timedelta(minutes=time)
    max_failed_attempts = no_attepmts

    if int(failed_login_attempts) >= max_failed_attempts:
        time_since_last_failed = datetime.now() - datetime.strptime(last_failed_login, '%Y-%m-%d %H:%M:%S')
        if time_since_last_failed < lock_time:
            return True
    return False
def create_delay():
    time.sleep(random.randint(500, 1500)/1000)
    

