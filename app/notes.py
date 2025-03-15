import base64
import bleach
import markdown
import os
from database import get_user_private_key, insert_note, get_all_notes, get_user_detailed_notes, get_note, get_note_with_pub_key
from flask import Blueprint, render_template, request, session, redirect, url_for
from note_functions import sign_note, verify_signature, hash_note
from encrypt_functions import decrypt_data_aes_gcm, generate_encryption_key
from validation_functions import is_valid_note_title

from dotenv import load_dotenv

load_dotenv()

PRIVATE_KEY_PEPPER = base64.b64decode(os.getenv("PRIVATE_KEY_PEPPER").encode('utf-8'))

notes_bp = Blueprint('notes', __name__)

ALLOWED_TAGS = frozenset(list(bleach.sanitizer.ALLOWED_TAGS) + ['p', 'br', 'h1', 'h2', 'h3', 'strong', 'em', 'ul', 'ol', 'li', 'a', 'img'])
ALLOWED_ATTRIBUTES = {'a': ['href', 'title'], 'img': ['src', 'alt']}

@notes_bp.route('/notes', methods=['POST', 'GET'])
def add_note():
    if 'username' not in session:
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        note_content = request.form['note']
        note_title = request.form['title']
        password = request.form['password']
        username = session['username']

        if request.form.get('honeypot'):
            session.clear()
            return redirect(url_for('home.home', error="Suspicious activity detected! You've been logged out."))
        
        if len(note_title) < 3 or len(note_title) > 100:
            return render_template('add_note.html', error="Title must be between 3 and 100 characters.")
        if not is_valid_note_title(note_title):
            return render_template('add_note.html', error="Title contains forbidden characters")
        if len(note_content.strip()) == 0:
            return render_template('add_note.html', error="Note cannot be empty.")
        if len(note_content) > 5000:
            return render_template('add_note.html', error="Content cannot exceed 5000 characters.")

        user = get_user_private_key(username)

        if user:
            try:
                private_key_full = base64.b64decode(user['private_key'])
                iv = private_key_full[:12]
                tag = private_key_full[12:28]
                salt = private_key_full[28:44]
                private_key_encrypted = private_key_full[44:]
                
                decryption_key = generate_encryption_key(password, PRIVATE_KEY_PEPPER + salt)
                
                private_key_text = decrypt_data_aes_gcm(private_key_encrypted, decryption_key, iv, tag)
            except Exception as e:
                return render_template('add_note.html', error="Invalid password")
            
             
            
            rendered_html = markdown.markdown(note_content, extensions=['extra'], output_format='html')
            sanitized_html = bleach.clean(rendered_html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)

            signature = sign_note(sanitized_html, private_key_text)
            insert_note(user['id'], note_title, sanitized_html, base64.b64encode(signature).decode())
            
        return redirect(url_for('notes.view_notes'))
    
    return render_template('add_note.html')


@notes_bp.route('/notes/view')
def view_notes():
    if 'username' not in session:
        return redirect(url_for('auth.login'))
    all_notes = get_all_notes()

    return render_template('view_notes.html', notes=all_notes)

@notes_bp.route('/notes/<string:note_user>/view')
def view_user_notes(note_user):
    if 'username' not in session:
        return redirect(url_for('auth.login'))
    user_notes = get_user_detailed_notes(note_user)

    return render_template('user_notes.html', notes=user_notes, noteuser=note_user)

@notes_bp.route('/notes/<int:note_id>/verify')
def verify_note_signature(note_id):
    if 'username' not in session:
        return redirect(url_for('auth.login'))
    note = get_note_with_pub_key(note_id)
    
    if note:
        public_key_text = note['public_key']
        public_key_base64 = base64.b64encode(public_key_text).decode()
        signature_text = note['signature']
        signature = base64.b64decode(note['signature'])
        note_content = note['note']
        note_content_base64 = base64.b64encode(note_content.encode()).decode()
        note_hash_base64 = base64.b64encode(hash_note(note_content).digest()).decode()
        is_valid = verify_signature(note_content, signature, public_key_text)

        if is_valid:
            verification_status = 'Signature is valid.'
        else:
            verification_status = 'Signature is incorrect!'

        return render_template('verify_signature.html', note=note, verification_status=verification_status, public_key=public_key_base64
                               , signature=signature_text, note_hash = note_hash_base64, note_content=note_content_base64)
    
    return redirect(url_for('notes.view_notes'))

@notes_bp.route('/notes/<int:note_id>/view')
def view_note_page(note_id):
    if 'username' not in session:
        return redirect(url_for('auth.login'))
    
    note = get_note(note_id)
    note = dict(note)
    note['note'] = bleach.clean(note['note'], tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)
    return render_template('single_note.html', note=note)

