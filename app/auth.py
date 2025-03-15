import base64
import os
from flask import Blueprint, render_template, request, session, redirect, url_for
from auth_functions import generate_rsa_keys, generate_totp_qr_code, generate_totp_secret, hash_password, is_address_locked, password_strength, verify_password, verify_totp, create_delay
from database import get_attempts, increment_failed_attempts, get_user_by_email, get_user_by_username, insert_user, log_login, reset_attempts
from encrypt_functions import decrypt_totp_secret, encrypt_data_aes_gcm, generate_encryption_key
from validation_functions import is_valid_email, is_valid_totp_code, is_valid_username, is_valid_password
from Crypto.Random import get_random_bytes
from dotenv import load_dotenv
 
load_dotenv()

TOTP_SECRET_KEY = base64.b64decode(os.getenv("TOTP_SECRET_KEY").encode('utf-8'))
PRIVATE_KEY_PEPPER = base64.b64decode(os.getenv("PRIVATE_KEY_PEPPER").encode('utf-8'))

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        repeat_password = request.form['repeat_password']
        password_strength_label = password_strength(password)
        ip_address = request.remote_addr

        if request.form.get('honeypot'):
            return redirect(url_for('home.home', error="Suspicious activity detected!"))
        if len(email) > 254:
            return render_template('register.html', error='Given email is too long.')
        if not is_valid_email(email):
            return render_template('register.html', error='Given email is incorrect.')
        if len(username) > 20 or len(username) < 3:
            return render_template('register.html', error='Username must be between 3 and 20 characters.')
        if not is_valid_username(username):
            return render_template('register.html', error='Given username contains forbidden characters.')
        if not repeat_password == password:
            return render_template('register.html', error='Passwords do not match.')
        if not is_valid_password(password):
            return render_template('register.html', error='Password must consist of at least 8 characters.')
        if password_strength_label == 'Weak':
            return render_template('register.html', error='Given password is too weak.')

        attempts = get_attempts(ip_address, 'register')

        if attempts and is_address_locked(attempts['last_failed_attempt'], attempts['failed_attempts'], 1, 5):
            return render_template('register.html', error='Too many attempts! Please try again later.')
        user = get_user_by_email(email)
        if user:
            increment_failed_attempts(ip_address, 'register')
            create_delay()
            return render_template('register.html', error='Account for given email address already exists!')
        user = get_user_by_username(username)
        if user:
            increment_failed_attempts(ip_address, 'register')
            create_delay()
            return render_template('register.html', error='Given username is already taken!')
        
        totp_secret = generate_totp_secret()
        totp_salt = get_random_bytes(16)
        totp_key = generate_encryption_key(TOTP_SECRET_KEY, totp_salt)
        totp_secret_encrypted, totp_iv, totp_tag = encrypt_data_aes_gcm(totp_secret.encode('utf-8'), totp_key)
        totp_full = totp_iv + totp_tag + totp_salt + totp_secret_encrypted
        private_key, public_key = generate_rsa_keys()

        hashed_password = hash_password(password)
        salt = get_random_bytes(16)
        encryption_key = generate_encryption_key(password, PRIVATE_KEY_PEPPER+salt)
        private_key_encrypted, iv, tag = encrypt_data_aes_gcm(private_key, encryption_key)
        private_key_full = iv + tag + salt + private_key_encrypted

        insert_user(
            username, email, hashed_password,
            base64.b64encode(totp_full).decode(),
            base64.b64encode(private_key_full).decode(), public_key
        )

        img_byte_arr = generate_totp_qr_code(totp_secret, username)
        qr_code_base64 = base64.b64encode(img_byte_arr.getvalue()).decode('utf-8')
        if attempts:
            reset_attempts(ip_address, 'register')
        create_delay()
        return render_template('register_qr.html', qr_code_img=qr_code_base64)

    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        totp_code = request.form['totp_code']
        user_agent = request.headers.get('User-Agent')
        ip_address = request.remote_addr

        if request.form.get('honeypot'):
            return redirect(url_for('home.home', error="Suspicious activity detected!"))
        if len(username) > 20 or len(username) < 3:
            return render_template('login.html', error='Username must be between 3 and 20 characters.')
        if not is_valid_username(username):
            return render_template('login.html', error='Given username contains forbidden characters.')
        if not is_valid_totp_code(totp_code):
            return render_template('login.html', error='2fa code must be a 6-digit number.')

        user = get_user_by_username(username)
        attempts = get_attempts(ip_address, 'login')

        if attempts and is_address_locked(attempts['last_failed_attempt'], attempts['failed_attempts'], 1, 5):
            return render_template('login.html', error='Too many attempts! Please try again later.')

        if user and verify_password(user['password'], password):
            totp_secret = decrypt_totp_secret(user['totp_secret'])
            if verify_totp(totp_secret, totp_code):
                session.permanent = True
                session['username'] = username

                if attempts:
                    reset_attempts(ip_address, 'login')
                log_login(user['id'], ip_address, user_agent)
                create_delay()
                return redirect(url_for('home.home'))

            increment_failed_attempts(ip_address, 'login')
            create_delay()
            return render_template('login.html', error='Invalid credentials')

        increment_failed_attempts(ip_address, 'login')
        create_delay()
        return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home.home'))

