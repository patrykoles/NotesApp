import base64
import os
from itsdangerous import URLSafeTimedSerializer
from Crypto.Random import get_random_bytes
from flask import Blueprint, render_template, request, session, redirect, url_for, current_app
from auth_functions import generate_rsa_keys, hash_password, verify_password, verify_totp, password_strength, create_delay, is_address_locked
from database import get_user_by_username, get_user_notes, update_note_signature, update_user, get_user_by_email, get_attempts, reset_attempts, increment_failed_attempts
from encrypt_functions import encrypt_data_aes_gcm, generate_encryption_key, decrypt_data_aes_gcm, decrypt_totp_secret
from validation_functions import is_valid_email, is_valid_totp_code, is_valid_password
from note_functions import sign_note, verify_signature
from dotenv import load_dotenv

load_dotenv()

TOTP_SECRET_KEY = base64.b64decode(os.getenv("TOTP_SECRET_KEY").encode('utf-8'))
PRIVATE_KEY_PEPPER = base64.b64decode(os.getenv("PRIVATE_KEY_PEPPER").encode('utf-8'))


pass_bp = Blueprint('pass_control', __name__)

@pass_bp.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        repeat_password = request.form['repeat_password']
        totp_code = request.form['totp_code']
        username = session['username']
        password_strength_label = password_strength(new_password)
        if not is_valid_totp_code(totp_code):
            return render_template('change_password.html', error='2fa code must be a 6-digit number.')
        if not repeat_password == new_password:
            return render_template('change_password.html', error='Passwords do not match.')
        if not is_valid_password(new_password):
            return render_template('change_password.html', error='Password must consist of at least 8 characters')
        if password_strength_label == 'Weak':
            return render_template('change_password.html', error='Given password is too weak')
        if request.form.get('honeypot'):
            session.clear()
            return redirect(url_for('home.home', error="Suspicious activity detected! You've been logged out."))
        
        user = get_user_by_username(username)

        if user:
            if not verify_password(user['password'], current_password):
                return render_template('change_password.html', error="Incorrect credentials.")
            totp_secret = decrypt_totp_secret(user['totp_secret'])
            if not verify_totp(totp_secret, totp_code):
                return render_template('change_password.html', error="Incorrect credentials.")
        
            hashed_password = hash_password(new_password)
            new_private_key, new_public_key = generate_rsa_keys()

            salt = get_random_bytes(16)
            encryption_key = generate_encryption_key(new_password, PRIVATE_KEY_PEPPER+salt)

            new_private_key_encrypted, new_iv, new_tag = encrypt_data_aes_gcm(new_private_key, encryption_key)
            new_private_key_full = new_iv + new_tag + salt + new_private_key_encrypted 

            user_notes = get_user_notes(user['id'])

            for note in user_notes:
                old_public_key_text = note['public_key']
                old_signature = base64.b64decode(note['signature'])
                note_content = note['note']
                is_valid = verify_signature(note_content, old_signature, old_public_key_text)
                if is_valid:
                    signature = sign_note(note_content, new_private_key)
                    update_note_signature(base64.b64encode(signature).decode(), note['id'])
            update_user(hashed_password, base64.b64encode(new_private_key_full).decode(), new_public_key, username)
            

            return redirect(url_for('home.home', message="Password changed successfully!"))

        return render_template('change_password.html', error="User not found.")

    return render_template('change_password.html')

@pass_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    ip_address = request.remote_addr
    attempts = get_attempts(ip_address, 'reset')
    if attempts:
        if is_address_locked(attempts['last_failed_attempt'], attempts['failed_attempts'], 15, 5):
            return redirect(url_for('home.home', error='Too many attempts! Try again later.'))
    try:
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        email = serializer.loads(token, salt="password-reset", max_age=3600)
        if attempts:
                reset_attempts(ip_address, 'reset')
    except:
        increment_failed_attempts(ip_address, 'reset')
        return "Token is expired", 403
    
    if request.method == 'POST':
        if request.form.get('honeypot'):
            return redirect(url_for('home.home', error="Suspicious activity detected!"))
        new_password = request.form['password']
        repeat_password = request.form['repeat_password']
        password_strength_label = password_strength(new_password)
        if not repeat_password == new_password:
                return render_template('reset_password.html', error='Passwords do not match.', token=token)
        if not is_valid_password(new_password):
                return render_template('reset_password.html', token=token, error='Password must consist of at least 8 characters')
        if password_strength_label == 'Weak':
            return render_template('reset_password.html', error='Given password is too weak', token=token)

        user = get_user_by_email(email)
        if user:
            hashed_password = hash_password(new_password)

            new_private_key, new_public_key = generate_rsa_keys()

            salt = get_random_bytes(16)
            encryption_key = generate_encryption_key(new_password, PRIVATE_KEY_PEPPER + salt)

            new_private_key_encrypted, new_iv, new_tag = encrypt_data_aes_gcm(new_private_key, encryption_key)
            new_private_key_full = new_iv + new_tag + salt + new_private_key_encrypted

            user_notes = get_user_notes(user['id'])

            for note in user_notes:
                old_public_key_text = note['public_key']
                old_signature = base64.b64decode(note['signature'])
                note_content = note['note']
                is_valid = verify_signature(note_content, old_signature, old_public_key_text)
                if is_valid:
                    signature = sign_note(note_content, new_private_key)
                    update_note_signature(base64.b64encode(signature).decode(), note['id'])
            update_user(hashed_password, base64.b64encode(new_private_key_full).decode(), new_public_key, user['username'])

            create_delay()
            return redirect(url_for('home.home', message="Password changed successfully!"))
        create_delay()
        return redirect(url_for('home.home', error='Account for given email does not exist!'))
    
    return render_template('reset_password.html', token=token)

@pass_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        if request.form.get('honeypot'):
            return redirect(url_for('home.home', error="Suspicious activity detected!"))

        user_email = request.form['email']
        ip_address = request.remote_addr
        if len(user_email) > 254:
            return render_template('forgot_password.html', error='Given email is too long.')
        if not is_valid_email(user_email):
            return render_template('forgot_password.html', error='Given email is incorrect.')

        attempts = get_attempts(ip_address, 'forgot')
        if attempts:
            if is_address_locked(attempts['last_failed_attempt'], attempts['failed_attempts'], 15, 5):
                return render_template('forgot_password.html', error='Too many attepmts! Please try again later.')
        user = get_user_by_email(user_email)
        if user:
            serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
            reset_token = serializer.dumps(user_email, salt="password-reset")
            reset_url = f"https://localhost/reset_password/{reset_token}"
            print(f"Message sent to: {user_email}")
            print(f"Password recovery link: {reset_url}")
            if attempts:
                reset_attempts(ip_address, 'forgot')    
            create_delay()
            return redirect(url_for('home.home', message="Recovery link sent to given email address."))        
        increment_failed_attempts(ip_address, 'forgot')
        create_delay()
        return render_template('forgot_password.html', error='Account for given email does not exist!')    

    return render_template('forgot_password.html')

