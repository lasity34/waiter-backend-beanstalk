import os
import logging
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import text

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
application = Flask(__name__)
logger.info("Flask app initialized")

# Configuration
application.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
application.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

if not application.config['SECRET_KEY']:
    logger.error("No SECRET_KEY set for Flask application")
    raise ValueError("No SECRET_KEY set for Flask application")

if not application.config['SQLALCHEMY_DATABASE_URI']:
    logger.error("No DATABASE_URL set for Flask application")
    raise ValueError("No DATABASE_URL set for Flask application")

# Initialize extensions
db = SQLAlchemy(application)
login_manager = LoginManager(application)

# CORS configuration
allowed_origins = os.getenv('ALLOWED_ORIGINS', 'https://d1ozcmsi9wy8ty.cloudfront.net,http://localhost:3000').split(',')
CORS(application, resources={r"/*": {"origins": allowed_origins}})

@application.after_request
def after_request(response):
    origin = request.headers.get('Origin')
    if origin in allowed_origins:
        response.headers.add('Access-Control-Allow-Origin', origin)
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    role = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Shift(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('shifts', lazy=True))
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    status = db.Column(db.String(20), default='requested')
    shift_type = db.Column(db.String(20), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@application.route('/')
def hello():
    return jsonify({"message": "Welcome to the Waiter Scheduling App"}), 200

@application.route('/db-test')
def db_test():
    try:
        result = db.session.execute(text('SELECT 1'))
        return jsonify({"message": "Database connection successful", "result": result.scalar()}), 200
    except Exception as e:
        return jsonify({"message": f"Database connection failed: {str(e)}"}), 500

@application.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and user.check_password(data['password']):
        login_user(user)
        return jsonify({
            'message': 'Logged in successfully',
            'role': user.role,
            'name': user.name,
            'id': user.id
        })
    return jsonify({'message': 'Invalid email or password'}), 401

@application.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'})

def init_db():
    with application.app_context():
        try:
            db.create_all()
            logger.info("Database tables created successfully")
            if not User.query.filter_by(email=os.getenv('ADMIN_EMAIL')).first():
                admin_user = User(
                    email=os.getenv('ADMIN_EMAIL'),
                    role='manager',
                    name='Admin'
                )
                admin_user.set_password(os.getenv('ADMIN_PASSWORD'))
                db.session.add(admin_user)
                db.session.commit()
                logger.info("Admin user created successfully")
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            raise

# Initialize the database
init_db()

if __name__ == '__main__':
    application.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))