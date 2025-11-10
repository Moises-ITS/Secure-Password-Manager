from cryptography.fernet import Fernet
import pyotp, bcrypt, json, os, qrcode, re
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import time
from datetime import datetime
import random
import smtplib
from email.mime.text import MIMEText
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv

load_dotenv()
#--------------------------
#flask setup
#---------------------------
app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), "static"), template_folder=os.path.join(os.path.dirname(__file__), "templates"))
app.secret_key = os.getenv("SECRET_KEY")
#------------------------------
#SQLite database
#------------------------------
app.config['SQLALCHEMY_DATABASE_URI' ] = os.getenv("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    totp_secret = db.Column(db.String(200), nullable=False)
    verification_token = db.Column(db.String(6), nullable=False)
    token_expiry = db.Column(db.Float, nullable=True)
    login_attempts = db.Column(db.Integer, default=0)
    lockout_time = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class LoginLog(db.Model):

    id = db.Column(db.Integer, unique=True, nullable=False, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='logs')

class vault(db.Model):

    id = db.Column(db.Integer, unique=True, nullable=False, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vaultsite = db.Column(db.String(100), nullable=False)
    vaultuser = db.Column(db.String(100), nullable=False)
    vaultpw = db.Column(db.String(300), nullable=False)
    timecreated = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="vault_entries", lazy=True)

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
#------------------------------
#helper functions
#-------------------------------


def is_valid_email(email):
    try:
        valid = validate_email(email)
        return True
    except EmailNotValidError:
        return False

def generate_verification_token():
    token = str(random.randint(100000, 999999))
    expiration = time.time() + 600
    return token, expiration
def send_email(user_email, token):
    try:
        msg = MIMEText(f"Your verification token is: {token}")
        msg["Subject"] = "Login Verification"
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = user_email
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, user_email, msg.as_string())
    except smtplib.SMTPException as e:
        print(f"Error: {e}")
    except smtplib.Exception as e:
        print(f"[ERROR] SMTP error occured: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")

def send_login_error_email(user_email):
    try:
        msg = MIMEText(f"More than 3 failed login attempts have been made to your account, as a result your account has been temporarily locked")
        msg["Subject"] = "Login Verification"
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = user_email
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, user_email, msg.as_string())
    except smtplib.SMTPException as e:
        print(f"Error: {e}")
    except smtplib.Exception as e:
        print(f"[ERROR] SMTP error occured: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")

def verify_token(token):
    email = session.get("email")
    user = User.query.filter_by(email=email).first()
    if not email:
        return False, "User must sign in first"
    if not token.isdigit() or len(token) >= 7:
        return False, "Invalid Token"
    if user.lockout_time is not None and time.time() < user.lockout_time:
        return False, f"User is locked out for {user.lockout_time}"
    if not user.verification_token or user.token_expiry and time.time() > user.token_expiry:
        return False, "Token expired or not set, go back to login for a new token"
    if user.verification_token != token:
        user.login_attempts += 1
        if user.login_attempts >= 3:
            user.lockout_time = time.time() + 300
            user.login_attempts = 0
            db.session.commit()
            send_login_error_email(email)
            remaining = int((user.lockout_time - time.time()) / 60)
            return False, f"Too many incorrect codes, account will be locked out for {remaining} minute(s)"
        db.session.commit()
        return False, "Incorrect Token"
    return True, "Correct Token"

def password_complexity(password):
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=;']", password):
        return False, "Password must include at least one special character."

    return True, "Password is strong."

def load_key():
    with open("secret.key", "rb") as key_file:
        return key_file.read()

def encrypt_password(plain_password):
    fernet = Fernet(load_key())
    return fernet.encrypt(plain_password.encode()).decode()

def decrypt_password(encrypted_password):
    fernet = Fernet(load_key())
    return fernet.decrypt(encrypted_password.encode()).decode()

#----------------------------------------------
# functions
#----------------------------------------------

def login_user(email, password):
    email = email.strip()
    password = password.strip()
    user = User.query.filter_by(email=email).first()

    if not user:
        return False, "Email does not exist"

    if user.lockout_time and time.time() < user.lockout_time:
        remaining = int((user.lockout_time - time.time()) / 60)
        return False, f"Too many failed attempts. Try again in {remaining} minute(s)"
    
    if not bcrypt.checkpw(password.encode(), user.password.encode()):
        user.login_attempts += 1
        if user.login_attempts >= 3:
            user.lockout_time = time.time() + 300
            user.login_attempts = 0
            db.session.commit()
            send_login_error_email(email)
            return False, "Too many failed attempts. You are locked out for 5 minutes."
        db.session.commit()
        return False, "Incorrect Password"
    session["email"] = user.email
    session["username"] = user.username

    user.login_attempts = 0
    user.lockout_time = None
    db.session.commit()
    
    log = LoginLog(user_id=user.id)
    db.session.add(log)
    db.session.commit()

    return True, "login successful!"

def register_user(username, email, password):
    fernet = Fernet(load_key())
    username = username.strip()
    password = password.strip()
    
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return False, "email already exists."

    secret = pyotp.random_base32()
    encrypted_secret = fernet.encrypt(secret.encode()).decode()
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    new_user = User(
        username=username, 
        email=email, 
        password=hashed_password, 
        totp_secret=encrypted_secret, 
        verification_token='', 
        token_expiry=None)
    db.session.add(new_user)
    db.session.commit()

    return True, "Successfully created User."

def verify_code(token):
    username = session.get("username")
    user = User.query.filter_by(username=username).first()
    email = session.get("email")
    fernet = Fernet(load_key())
    secret = fernet.decrypt(user.totp_secret.encode()).decode()

    totp = pyotp.TOTP(secret)
    if not token.isdigit() or len(token) >= 7:
        return False, f"Invalid Token"
    if not totp.verify(token):
        user.login_attempts += 1
        if user.login_attempts >= 3:
            user.lockout_time = time.time() + 300
            user.login_attempts = 0
            db.session.commit()
            send_login_error_email(email)
            return False, f"Too many failed attempts. You are locked out for {user.lockout_time / 60}"
        db.session.commit()
        flash("Incorrect Token", "warning")
    return True, "Valid Token"

def add_pw(vaultsite, vaultusername, vaultpw):
    try:
        current_user = User.query.filter_by(email=session["email"]).first()
        encrypted_pw = encrypt_password(vaultpw)
        new_entry = vault(
            user_id=current_user.id,
            vaultsite=vaultsite,
            vaultuser=vaultusername,
            vaultpw=encrypted_pw
        )
        db.session.add(new_entry)
        db.session.commit()

        return True
    except:
        return False
    
def change_pw(current_password, new_password, verify_password):
    email = session.get("email")
    user = User.query.filter_by(email=email).first()
    if not bcrypt.checkpw(current_password.encode(), user.password.encode()):
        return False, "Wrong current password"
    if new_password != verify_password:
        return False, "both passwords do not match"
    if current_password == new_password:
        return False, "New password cannot be the previous password"
    hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    user.password = hashed_password
    db.session.commit()
    return True, "Password Changed"


def qr_code():
    email = session.get("email")
    username = session.get("username")
    if not email:
        flash("Please login first.", "danger")
        return redirect(url_for("login"))
    user = User.query.filter_by(email=email).first()
    fernet = Fernet(load_key())
    secret = fernet.decrypt(user.totp_secret.encode()).decode()

    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="APM PW Manager")

    qr = qrcode.QRCode(
        version=1,  # 1 = smallest size, can increase if needed
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,  # each box will be 10x10 pixels
        border=4      # border width (minimum is 4 for most scanners)
    )
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    if not os.path.exists("static"):
        os.makedirs("static")

    qr_filename = f'{email}_qrcode.png'
    qr_path = os.path.join(app.static_folder, qr_filename)
    img.save(qr_path)

    session["qr_path"] = qr_filename

    
#----------------------------------------------
#Routes
#---------------------------------------------

@app.route("/", endpoint="index")
def menu():
    return render_template("index.html")

@app.route("/registerpw", methods=["GET", "POST"])
def registerpw():
    if "email" not in session:
        flash("Login First", "danger")
        return redirect(url_for("login"))
    if request.method == "POST":
        site_name = request.form.get("site_name")
        site_username = request.form.get("site_username")
        site_pw = request.form.get("site_pw")
        success = add_pw(site_name, site_username, site_pw)
        if not success:
            flash("Password Failed to Register", "danger")
            return redirect(url_for("registerpw"))
        flash("successfully saved password", "success")
        return redirect(url_for("registerpw"))
    return render_template("registerpw.html")

@app.route("/viewpw")
def viewpw():
    if "email" not in session:
        flash("Please login first.", "danger")
        return redirect(url_for("login"))
    
    email = session.get("email")
    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        flash("Please make an account first", "danger")
        return redirect(url_for("register"))
    
    fernet = Fernet(load_key())
    vault_entries = []
    for entry in vault.query.filter_by(user_id=user.id).all():
        try:
            decrypted_pw = fernet.decrypt(entry.vaultpw.encode()).decode()
        except:
            decrypted_pw = "[Error decrypting]"
    
        vault_entries.append({
            "site_name": entry.vaultsite,
            "site_username": entry.vaultuser,
            "site_password": decrypted_pw,
            "created_at": entry.timecreated.strftime("%Y-%m-%d %H:%M")
        })
    return render_template("viewpw.html", vault_entries=vault_entries)

@app.route("/logintime")
def logintime():
    username = session.get("username")
    if not username:
        flash("Login first.", "warning")
        return redirect(url_for("login"))
    user = User.query.filter_by(username=username).first()
    logs = LoginLog.query.filter_by(user_id=user.id).order_by(LoginLog.timestamp.desc()).all()
    return render_template("logintime.html", logs=logs, username=username)

@app.route("/emailauth", methods=["GET", "POST"])
def emailauth():
    email = session.get("email")
    if not email:
        flash("Login First", "danger")
    user = User.query.filter_by(email=email).first()
    if request.method == "GET":
        if not user.verification_token or not user.token_expiry or time.time() > user.token_expiry:
            real_token, token_expiry = generate_verification_token()
            user.verification_token = real_token
            user.token_expiry = token_expiry
            db.session.commit()
            print(f"[DEBUG] Sending email: to {user.email} with token {real_token}")
            send_email(user.email, real_token)
            flash("email has been sent")
        return render_template("emailauth.html")

    if request.method == "POST":
        token = request.form.get("token")
        valid, msg = verify_token(token)
        if not valid:
            flash(msg, "danger")
            return redirect(url_for("emailauth"))
        user.verification_token = ''
        user.token_expiry = None
        user.login_attempts = 0
        user.lockout_time = None
        db.session.commit()

        flash("Successful", "success")
        return redirect(url_for("test"))
    return render_template("emailauth.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        
        valid, msg = password_complexity(password)
        if not valid:
            flash(msg, "danger")
            return redirect(url_for("register"))

        success, msg = register_user(username, email, password)
        if not success:
            flash(msg, "danger")
            return redirect(url_for("register"))

        flash(msg, "success")
        return redirect(url_for("home"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        if not is_valid_email(email):
            flash("invalid email", "warning")
            return redirect(url_for("login"))
        valid, msg = login_user(email, password)
        if not valid:
            flash(msg, "danger")
            return redirect(url_for("login"))
        return redirect(url_for("emailauth"))
    return render_template("login.html")

@app.route("/show_qr")
def show_qr():
    email = session.get("email")
    username = session.get("username")
    if not email:
        flash("Please login first.", "danger")
        return redirect(url_for("login"))
    user = User.query.filter_by(email=email).first()
    fernet = Fernet(load_key())
    secret = fernet.decrypt(user.totp_secret.encode()).decode()

    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="APM PW Manager")

    qr = qrcode.QRCode(
        version=1,  # 1 = smallest size, can increase if needed
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,  # each box will be 10x10 pixels
        border=4      # border width (minimum is 4 for most scanners)
    )
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    if not os.path.exists("static"):
        os.makedirs("static")

    qr_filename = f'{username}_qrcode.png'
    qr_path = os.path.join(app.static_folder, qr_filename)
    img.save(qr_path)

    session["qr_path"] = qr_filename

    return render_template("show_qr.html", qr_path=qr_filename)

@app.route("/test", methods=["GET", "POST"])
def test():
    if "email" not in session:
        flash("Please log in first", "warning")
        return redirect(url_for("login"))
    if request.method == "POST":
        token = request.form.get("token")
        valid, msg = verify_code(token)
        if not valid:
            flash(msg, "danger")
        flash(msg, "success")
        return redirect(url_for("home"))
    return render_template("test.html")

@app.route("/changepassword", methods=["GET", "POST"])
def changepassword():
    if "email" not in session:
        flash("login first", "warning")
        return redirect(url_for("login"))
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        verify_password = request.form.get("verify_password")
        valid, msg = change_pw(current_password, new_password, verify_password)
        if not valid:
            flash(msg, "warning")
            return redirect(url_for("changepassword"))
        flash(msg, "success")
        return redirect(url_for("home"))
    return render_template("changepassword.html")


@app.route("/home")
def home():
    if "email" not in session or "username" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    username = session["username"]
    return render_template("home.html", username=username)

@app.route("/Logout")
def Logout():
    session.pop("qr_path", None)
    session.pop("username", None)
    session.pop("email", None)
    flash("Logged out successfully", "success")
    return render_template("index.html")
    
#---------------------------------------------
#run app
#---------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
