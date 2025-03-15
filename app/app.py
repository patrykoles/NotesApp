from datetime import timedelta
from flask import Flask
from flask_wtf import CSRFProtect
from init_db import initialize_db
from home import home_bp
from auth import auth_bp
from notes import notes_bp
from pass_control import pass_bp
import base64
import os

encoded_secret_key = os.getenv("APP_SECRET_KEY")
secret_key = base64.b64decode(encoded_secret_key.encode('utf-8'))

app = Flask(__name__)
app.secret_key = secret_key
app.permanent_session_lifetime = timedelta(minutes=30)

csrf = CSRFProtect(app)

initialize_db()

app.register_blueprint(home_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(notes_bp)
app.register_blueprint(pass_bp)

@app.after_request
def set_csp_header(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data: https:;"
        "frame-ancestors 'none';"
    )
    return response

@app.after_request
def remove_server_header(response):
    response.headers.pop('Server', None)
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
