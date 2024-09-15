import os
import logging
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import text
from sqlalchemy.orm import joinedload
from werkzeug.exceptions import BadRequest

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
allowed_origins = [origin.strip() for origin in os.getenv('ALLOWED_ORIGINS', 'https://d1ozcmsi9wy8ty.cloudfront.net,http://localhost:3000').split(',')]
logger.info(f"Allowed origins: {allowed_origins}")

CORS(application, resources={r"/api/*": {
    "origins": allowed_origins, 
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], 
    "allow_headers": ["Content-Type", "Authorization"]
}}, supports_credentials=True)

@application.after_request
def after_request(response):
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
    return jsonify({"message": "Carin is a bitch"}), 200

@application.route('/api/db-test')
def db_test():
    try:
        user_count = User.query.count()
        return jsonify({'message': f'Database connection successful. User count: {user_count}'}), 200
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        return jsonify({'message': 'Database connection failed'}), 500
    
    
@application.route('/api/test-post', methods=['POST'])
def test_post():
    data = request.get_json()
    return jsonify({'message': 'POST request received', 'data': data}), 200


@application.route('/api/login', methods=['POST'])
def login():
    logger.info("Login attempt received")
    logger.info(f"Request headers: {request.headers}")
    
    try:
        data = request.get_json()
        logger.info(f"Parsed JSON data: {data}")
        
        if not data or 'email' not in data or 'password' not in data:
            logger.warning("Invalid login data received")
            return jsonify({'message': 'Invalid login data'}), 400

        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not user.check_password(data['password']):
            logger.warning(f"Failed login attempt for email: {data['email']}")
            return jsonify({'message': 'Invalid email or password'}), 401

        login_user(user, remember=data.get('remember', False))
        logger.info(f"Login successful for user: {user.email}")
        return jsonify({
            'message': 'Logged in successfully',
            'role': user.role,
            'name': user.name,
            'id': user.id
        })

    except Exception as e:
        logger.error(f"Exception in login route: {str(e)}", exc_info=True)
        return jsonify({'message': 'An error occurred during login'}), 500

@application.route('/api/test', methods=['GET'])
def test_route():
    return jsonify({"message": "API is working"}), 200

@application.route('/api/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'})

@application.route('/api/users', methods=['GET', 'POST'])
@login_required
def handle_users():
    if current_user.role != 'manager':
        return jsonify({'message': 'Unauthorized'}), 403
    
    if request.method == 'POST':
        data = request.json
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email already registered'}), 400
        new_user = User(email=data['email'], role=data['role'], name=data['name'])
        new_user.set_password(data['password'])
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created successfully', 'id': new_user.id}), 201
    else:
        users = User.query.all()
        return jsonify([{'id': u.id, 'name': u.name, 'email': u.email, 'role': u.role} for u in users])

@application.route('/api/users/<int:user_id>', methods=['PUT', 'DELETE'])
@login_required
def manage_user(user_id):
    if current_user.role != 'manager':
        return jsonify({'message': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'PUT':
        data = request.json
        user.name = data.get('name', user.name)
        user.email = data.get('email', user.email)
        user.role = data.get('role', user.role)
        if 'password' in data:
            user.set_password(data['password'])
        db.session.commit()
        return jsonify({'message': 'User updated successfully'})
    
    elif request.method == 'DELETE':
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})

@application.route('/api/shifts', methods=['GET', 'POST'])
@login_required
def handle_shifts():
    if request.method == 'POST':
        data = request.json
        user_id = data.get('user_id', current_user.id)
        
        if current_user.role != 'manager' and user_id != current_user.id:
            return jsonify({'message': 'Unauthorized'}), 403
        
        date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        
        existing_shift = Shift.query.filter_by(user_id=user_id, date=date).first()
        if existing_shift and current_user.role != 'manager':
            return jsonify({'message': 'You already have a shift on this day'}), 400
        
        new_shift = Shift(
            user_id=user_id,
            date=date,
            start_time=datetime.strptime(data['start_time'], '%H:%M').time(),
            end_time=datetime.strptime(data['end_time'], '%H:%M').time(),
            shift_type=data['shift_type'],
            status='approved' if current_user.role == 'manager' else 'requested'
        )
        db.session.add(new_shift)
        
        try:
            db.session.commit()
            return jsonify({'message': 'Shift created successfully', 'id': new_shift.id}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': 'Failed to create shift', 'error': str(e)}), 500
    
    else:  # GET request
        try:
            if current_user.role == 'manager':
                shifts = Shift.query.options(joinedload(Shift.user)).all()
            else:
                shifts = Shift.query.filter_by(user_id=current_user.id).all()
            
            return jsonify([{
                'id': shift.id,
                'user_id': shift.user_id,
                'user_name': shift.user.name,
                'date': shift.date.isoformat(),
                'start_time': shift.start_time.isoformat(),
                'end_time': shift.end_time.isoformat(),
                'status': shift.status,
                'shift_type': shift.shift_type,
                'is_current_user': shift.user_id == current_user.id
            } for shift in shifts]), 200
        except Exception as e:
            return jsonify({'message': 'Failed to fetch shifts', 'error': str(e)}), 500

@application.route('/api/shifts/<int:shift_id>', methods=['PUT', 'DELETE'])
@login_required
def manage_shift(shift_id):
    if current_user.role != 'manager':
        return jsonify({'message': 'Unauthorized'}), 403
   
    shift = Shift.query.get_or_404(shift_id)
    
    if request.method == 'PUT':
        data = request.json
        
        if 'shift_type' in data:
            shift.shift_type = data['shift_type']
            if data['shift_type'] == 'morning':
                shift.start_time = datetime.strptime('09:00', '%H:%M').time()
                shift.end_time = datetime.strptime('17:00', '%H:%M').time()
            elif data['shift_type'] == 'evening':
                shift.start_time = datetime.strptime('17:00', '%H:%M').time()
                shift.end_time = datetime.strptime('01:00', '%H:%M').time()
            elif data['shift_type'] == 'double':
                shift.start_time = datetime.strptime('09:00', '%H:%M').time()
                shift.end_time = datetime.strptime('01:00', '%H:%M').time()
        
        for field in ['status', 'date', 'user_id']:
            if field in data:
                if field == 'date':
                    setattr(shift, field, datetime.strptime(data[field], '%Y-%m-%d').date())
                else:
                    setattr(shift, field, data[field])

        db.session.commit()
        return jsonify({'message': 'Shift updated successfully'})
    
    elif request.method == 'DELETE':
        db.session.delete(shift)
        db.session.commit()
        return jsonify({'message': 'Shift deleted successfully'})

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