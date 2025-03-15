from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def sign_note(note, private_key):
    key = RSA.import_key(private_key)
    hash = hash_note(note)
    signature = pkcs1_15.new(key).sign(hash)
    return signature
def hash_note(note):
    hash = SHA256.new(note.encode())
    return hash

def verify_signature(note, signature, public_key):
    try:      
        key = RSA.import_key(public_key)
        hash = SHA256.new(note.encode())
        pkcs1_15.new(key).verify(hash, signature)
        return True
    except (ValueError, TypeError):
        return False