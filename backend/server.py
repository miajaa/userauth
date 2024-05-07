import logging
from sqlite3 import IntegrityError
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from flask_sqlalchemy import SQLAlchemy
import os
import re
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Set the secret key for JWT authentication
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# SQLite configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the SQLite database
db = SQLAlchemy(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='app.log',
    filemode='a'
)

# User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Create the database tables
with app.app_context():
    db.create_all()

# Google reCAPTCHA site secret
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')

# Function to generate JWT token
def generate_jwt_token(email):
    token = create_access_token(identity=email)
    return token

# Function to validate email format
def is_valid_email(email):
    email_regex = r'^[\w\.-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

# Route for user registration
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        if not data:
            logging.error("[NO_JSON_DATA] ERROR: No JSON data provided")
            return jsonify(error='not data: No JSON data provided'), 400
        
        email = data.get('email')
        password = data.get('password')
        recaptcha_response = data.get('recaptchaResponse')
        
        if not email or not password or not recaptcha_response:
            logging.error("[REQ_ERR] ERROR: Email, password, or recaptchaResponse missing in request")
            return jsonify(error='Email, password, or recaptchaResponse missing in request'), 400
        
        if not is_valid_email(email):
            logging.error("[EMAIL_ERR] ERROR: Invalid email format")
            return jsonify(error='Invalid email format'), 400
        
        recaptcha_verification = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={'secret': RECAPTCHA_SECRET_KEY, 'response': recaptcha_response}
        ).json()

        if not recaptcha_verification.get('success'):
            logging.error("[RECAPTCHA_ERR] ERROR: reCAPTCHA verification failed")
            return jsonify(error='reCAPTCHA verification failed'), 400
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            logging.error("[USR_ERR] ERROR: User already exists")
            return jsonify(error='User already exists'), 400
        
        if len(password) < 8 or not re.search("[a-z]", password) or not re.search("[A-Z]", password) \
                or not re.search("[0-9]", password) or not re.search("[!@#$%^&*()-_=+{};:,<.>]", password):
            logging.error("[WL_ERR] ERROR: Invalid password: Password complexity requirements not met ")
            return jsonify(error='Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.'), 400
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        token = generate_jwt_token(email)

        logging.info("[INFO-REG-SUCCESS] User registered successfully: %s", email)

        return jsonify(message='User registered successfully', token=token), 201

    except IntegrityError:
        db.session.rollback()
        logging.error("[ERR-REG-INT] User registration failed: IntegrityError")
        return jsonify(error='User already exists'), 400
    
    except Exception as e:
        logging.error("[ERR-REG-FAIL] ERROR: User registration failed: %s", str(e))
        return jsonify(error='Registration failed'), 500

# Route for user login
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return jsonify(error='Missing email or password in request'), 400

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.email)
            return jsonify(token=access_token), 200
        else:
            return jsonify(error='Incorrect email or password'), 401
    except Exception as e:
        logging.error("Login failed: %s", str(e))
        return jsonify(error='Login failed'), 500

# Route for OAuth2 authentication callback
@app.route('/api/oauth2/callback', methods=['GET'])
def oauth2_callback():
    try:
        access_token = request.args.get('access_token')
        if not access_token:
            return jsonify(error='Access token missing'), 400

        verify_token_url = 'https://www.googleapis.com/oauth2/v3/tokeninfo'
        response = requests.get(verify_token_url, params={'access_token': access_token})
        if response.status_code == 200:
            user_info = response.json()
            email = user_info.get('email')
            if email:
                access_token = create_access_token(identity=email)
                return jsonify(token=access_token), 200
            else:
                return jsonify(error='Email not found in user info'), 400
        else:
            return jsonify(error='Failed to verify access token'), 400

    except Exception as e:
        logging.error("OAuth2 callback failed: %s", str(e))
        return jsonify(error='OAuth2 callback failed'), 500

if __name__ == '__main__':
    app.run(debug=True)
