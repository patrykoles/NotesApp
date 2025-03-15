from flask import Blueprint, render_template, request, session
from database import get_login_logs

home_bp = Blueprint('home', __name__)

@home_bp.route('/')
def home():
    error = request.args.get('error')
    message = request.args.get('message')
    
    if 'username' in session:
        logs = get_login_logs(session['username'])
        return render_template('index.html', username=session['username'], error=error, message=message, logs=logs)
    return render_template('index.html', username=None, error=error, message=message)