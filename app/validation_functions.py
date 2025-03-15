import re

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,255}\.[a-zA-Z]{2,}$'
    if len(email) > 254:
        return False
    return re.fullmatch(pattern, email) is not None

def is_valid_username(username):
    pattern = r'^[a-zA-Z0-9_-]{3,20}$'
    return re.fullmatch(pattern, username) is not None

def is_valid_totp_code(totp_code):
    pattern = r'^[0-9]{6}$'
    return re.fullmatch(pattern, totp_code) is not None
def is_valid_note_title(title):
    pattern = r'^[a-zA-Z0-9 _-]{3,100}$'
    return re.fullmatch(pattern, title) is not None
import re

def is_valid_password(password):
    if len(password) < 8:
        return False
    return True