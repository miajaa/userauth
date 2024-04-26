from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from flask_sqlalchemy import SQLAlchemy
import os
import secrets
import re
import requests

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Set the secret key for JWT authentication
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)

# SQLite configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_data.db'  # Changed database name to user_data.db
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the SQLite database
db = SQLAlchemy(app)

# User model
class User(db.Model):
    __tablename__ = 'users'  # Specify the table name explicitly
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Create the database tables
with app.app_context():
    db.create_all()

# Google reCAPTCHA site secret
RECAPTCHA_SECRET_KEY = '6LcHELQpAAAAAJlJwCg4qIAyP2070MZoN6GLfhjN'

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data['email']
        password = data['password']
        recaptcha_response = data['recaptchaResponse']  # Get reCAPTCHA response from the frontend
        
        # Verify the reCAPTCHA response with Google's reCAPTCHA API
        recaptcha_verification = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={'secret': RECAPTCHA_SECRET_KEY, 'response': recaptcha_response}
        ).json()

        # Check if reCAPTCHA verification was successful
        if not recaptcha_verification['success']:
            return jsonify(error='reCAPTCHA verification failed'), 400
        
        # Check if the user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify(error='User already exists'), 400
        
        # Check password strength
        if len(password) < 8 or not re.search("[a-z]", password) or not re.search("[A-Z]", password) \
                or not re.search("[0-9]", password) or not re.search("[!@#$%^&*()-_=+{};:,<.>]", password):
            return jsonify(error='Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.'), 400
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # Decode the hashed password
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify(message='User registered successfully'), 201
    except Exception as e:
        print(e)
        return jsonify(error='Registration failed'), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')  # Use .get() to avoid KeyError if email is missing
        password = data.get('password')  # Use .get() to avoid KeyError if password is missing
        if not email or not password:
            return jsonify(error='Missing email or password in request'), 400

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.email)
            return jsonify(token=access_token), 200
        else:
            return jsonify(error='Incorrect email or password'), 401
    except Exception as e:
        print(e)
        return jsonify(error='Login failed'), 500
        
if __name__ == '__main__':
    app.run(debug=True)
