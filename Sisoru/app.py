from flask import Flask, request, jsonify, session, render_template, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import os
import traceback

app = Flask(__name__)

# Enable CORS for all domains and allow credentials
CORS(app, supports_credentials=True)

# Flask Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database location
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Replace with a secure key in production
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # Allow cross-origin cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Cookies are sent over HTTPS

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Set up the static folder for serving HTML files
frontend_path = os.path.join(os.getcwd(), 'frontend')


# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

# Create database tables
with app.app_context():
    db.create_all()

# Default route to serve the login page
@app.route('/')
def home():
    return send_from_directory(frontend_path, 'login.html')  # Serve the login.html file

# Route for static assets (e.g., CSS, JS)
@app.route('/<path:path>')
def serve_static_file(path):
    return send_from_directory(frontend_path, path)

# Registration Endpoint
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid input data'}), 400

        # Check if user already exists
        existing_user = User.query.filter((User.username == data['username']) | (User.email == data['email'])).first()
        if existing_user:
            return jsonify({'error': 'Username or email already exists'}), 400

        # Hash password and create new user
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user = User(username=data['username'], email=data['email'], password=hashed_password)
        db.session.add(user)
        db.session.commit()

        return jsonify({'message': 'User created successfully'}), 201
    except Exception:
        db.session.rollback()
        traceback.print_exc()  # Debugging: Log the traceback for unexpected errors
        return jsonify({'error': 'An error occurred during registration'}), 500

# Login Endpoint
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid input data'}), 400

        # Check if user exists
        user = User.query.filter_by(email=data['email']).first()
        if user and bcrypt.check_password_hash(user.password, data['password']):
            session['user_id'] = user.id  # Store user ID in session
            return jsonify({'message': 'Login successful', 'redirect': 'index.html'}), 200

        return jsonify({'error': 'Invalid email or password'}), 401
    except Exception:
        traceback.print_exc()
        return jsonify({'error': 'An error occurred during login'}), 500

# Check Authentication Endpoint
@app.route('/check-auth', methods=['GET'])
def check_auth():
    try:
        if 'user_id' in session:
            return jsonify({'authenticated': True}), 200
        return jsonify({'authenticated': False}), 401
    except Exception:
        traceback.print_exc()
        return jsonify({'error': 'An error occurred during authentication check'}), 500

# Logout Endpoint
@app.route('/logout', methods=['POST'])
def logout():
    try:
        session.pop('user_id', None)  # Clear session
        return jsonify({'message': 'Logged out successfully'}), 200
    except Exception:
        traceback.print_exc()
        return jsonify({'error': 'An error occurred during logout'}), 500

if __name__ == '__main__':
    app.run(debug=True)
