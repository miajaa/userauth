import datetime
import hashlib
import logging
import secrets
from sqlite3 import IntegrityError
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, decode_token, get_jwt_identity, jwt_required
from jwt import ExpiredSignatureError, InvalidTokenError
from flask_sqlalchemy import SQLAlchemy
import os
import re
import requests
from dotenv import load_dotenv
from flask import jsonify, make_response
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables from .env file
load_dotenv()    
# Google reCAPTCHA site secret
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')

REDIRECT_URL = os.getenv('RECAPTCHA_SECRET_KEY')
# Secret key 
SECRET_KEY = os.getenv("SECRET_KEY")
################################################################

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Set the secret key for JWT authentication
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# SQLite configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

################################################################

# Initialize the Limiter with default settings
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["5 per minute"]
)

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
    accesstoken = db.Column(db.String(500), unique=True)

# Create the database tables
with app.app_context():
    db.create_all()

# Configure Flask Talisman with security headers
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'style-src': '\'self\' https://stackpath.bootstrapcdn.com',
        'script-src': '\'self\' https://stackpath.bootstrapcdn.com https://www.google.com',
        'img-src': '\'self\' https://www.google.com',
        'frame-src': '\'self\' https://www.google.com'
    },
    content_security_policy_nonce_in=['script-src']
)

#######################################################################

# Function to generate JWT token
def generate_jwt_token(email):
    token = create_access_token(identity=email)
    return token



# Function to validate email format
def is_valid_email(email):
    email_regex = r'^[\w\.-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

#######################################################################

## ---------------------------------ROUTES--------------------------------- ##

# Route for user registration
@limiter.limit("3 per minute")  
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
            data={'secret': RECAPTCHA_SECRET_KEY, 'response': recaptcha_response},
            timeout=5  # Adding a timeout of 5 seconds
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
        
        # Generate a unique salt for each user
        salt = hashlib.sha256(email.encode()).hexdigest()
        # Create a token with the user's email and the salt
        access_token = create_access_token(identity=email + salt)
        logging.info("[INFO-REG-SUCCESS] User registered successfully: %s", email)
        print("Generated ¨REGISTER Token:", access_token)

        return jsonify(message='User registered successfully', token=access_token), 201

    except IntegrityError:
        db.session.rollback()
        logging.error("[ERR-REG-INT] User registration failed: IntegrityError")
        return jsonify(error='User already exists'), 400
    
    except Exception as e:
        logging.error("[ERR-REG-FAIL] ERROR: User registration failed: %s", str(e))
        return jsonify(error='Registration failed'), 500
    
@app.route('/api/login', methods=['POST'])
@limiter.limit("3 per minute")
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            logging.error("[MISSING_ERR] ERROR: Missing email or password in request")
            return jsonify(error='Missing email or password in request'), 400

        # Sanitize inputs
        email = email.strip()
        password = password.strip()

        # Validate email format
        if not is_valid_email(email):
            logging.error("[EMAIL_ERR] ERROR: Invalid email format")
            return jsonify(error='Invalid email format'), 400

        # Check if the user exists and verify the password
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            # Generate a JWT token with user's email as identity
            access_token = create_access_token(identity=user.email)

            # Update the user's token column with the generated access token
            user.accesstoken = access_token
            db.session.commit()

            logging.info("Token created and saved, login successful, %s", str(email))
            print("Generated Access Token:", access_token)
            return jsonify(token=access_token), 200

        else:
            return jsonify(error='Incorrect email or password'), 401
    except Exception as e:
        logging.error("Login failed: %s", str(e))
        return jsonify(error='Internal server error'), 500

    
 #Route for the token verification   
@app.route('/api/check-token', methods=['POST'])
def check_token():
    try:
        data = request.json
        token = data.get('token')

        # Check if the token is valid for any user
        user = User.query.filter_by(accesstoken=token).first()
        is_valid_token = user is not None

        return jsonify(valid=is_valid_token), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

# Route for OAuth2 authentication callback
@app.route('/api/oauth2/callback', methods=['GET'])
def oauth2_callback():
    try:
        access_token = request.args.get('access_token')
        if not access_token:
            return jsonify(error='Access token missing'), 400

        verify_token_url = 'https://www.googleapis.com/oauth2/v3/tokeninfo'  # nosec
        response = requests.get(
            verify_token_url,
            params={'access_token': access_token},
            timeout=5  # Adding a timeout of 5 seconds
        )
        if response.status_code == 200:
            user_info = response.json()
            email = user_info.get('email')
            if email:
                access_token = create_access_token(identity=email)
                return jsonify(token=access_token), 200
            else:
                return jsonify(error='User not found in user info'), 400
        else:
            return jsonify(error='Failed to verify access token'), 400

    except Exception as e:
        logging.error("OAuth2 callback failed: %s", str(e))
        return jsonify(error='OAuth2 callback failed'), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        data = request.json
        token = data.get('token')

        if not token:
            return jsonify(error='Token missing'), 400

        user = User.query.filter_by(accesstoken=token).first()

        if user:
            # Nullify the access token in the database
            user.accesstoken = None
            db.session.commit()
            logging.info("User logged out successfully")
            return jsonify(message='Logout successful'), 200
        else:
            return jsonify(error='User not found'), 404
    except Exception as e:
        logging.error("Logout failed: %s", str(e))
        return jsonify(error='Internal server error'), 500

if __name__ == '__main__':
    app.run(debug=False)