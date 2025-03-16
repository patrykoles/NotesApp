# NotesApp
## Description
This Flask-based application provides a secure platform for posting and viewing markdown notes. Users can create, update, and view notes, which are validated and sanitized to prevent malicious content. Key security features include:

- Password Hashing: Passwords are securely hashed using industry-standard algorithms.
- Two-Factor Authentication (TOTP): Users can enable TOTP-based two-factor authentication for enhanced security.
- RSA Signatures: Notes are signed with RSA keys to ensure authenticity and integrity.
- CSRF Protection: The app uses CSRF tokens to prevent cross-site request forgery attacks.
- Honeypot Mechanisms: Extra measures to protect against bots and spam.
- Password Reset and Change: Users can securely reset and change their passwords.
- SSL Encryption: The app uses a self-signed SSL certificate to secure communication.
- Docker Deployment: The application is containerized with Docker, using uWSGI for application deployment and Nginx as a reverse proxy, all orchestrated with Docker Compose.
- Login History: Users can view their recent login activity.
- Password Strength Enforcement: Passwords are evaluated for strength using entropy, and failed login attempts are tracked to temporarily block suspicious IP addresses.
- Content Validation and Sanitization: All note content is validated and sanitized to avoid malicious input.
The application is designed with security in mind, ensuring that sensitive data is protected and that user interactions are secure.
## Deployment
In order to run the app use
```sh
docker-compose up --build
```
## Requirements
- flask
- uwsgi
- pyotp
- qrcode[pil]
- markdown
- bleach
- itsdangerous
- PyCryptodome
- passlib
- python-dotenv
- flask_wtf
