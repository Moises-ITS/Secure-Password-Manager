# Secure-Password-Manager
Secure Python/Flask Web app for password managing utilizing various authentication methods
# TOTP Flask App — Secure MFA Password Manager

A secure Flask web app demonstrating multi-factor authentication (MFA) and a password vault:
- Registration & login with bcrypt password hashing
- TOTP (Time-based One-Time Passwords) via `pyotp` and QR generation
- Email verification token (one-time code) during login
- Encrypted TOTP secrets with `cryptography.Fernet`
- SQLite + SQLAlchemy for persistent storage
- Login audit logs & per-user password vault (encrypted)
- Deployable to Render / Heroku / any WSGI host

## Features
- Secure password hashing with bcrypt
- Per-user TOTP secret encrypted on disk
- Email-based one-time verification tokens
- Login lockouts after repeated failures with notification
- Simple password vault — entries encrypted with Fernet
