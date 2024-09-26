import os
import logging
from flask import Flask, request, jsonify, make_response, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from sqlalchemy.orm import joinedload
from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from urllib.parse import quote
from itsdangerous import URLSafeTimedSerializer

# Load environment variables and configure logging
load_dotenv()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app and extensions
application = Flask(__name__)
logger.info("Flask app initialized")

# Configuration
application.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
application.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

if not application.config['SECRET_KEY']:
    raise ValueError("No SECRET_KEY set for Flask application")
if not application.config['SQLALCHEMY_DATABASE_URI']:
    raise ValueError("No DATABASE_URL set for Flask application")

db = SQLAlchemy(application)
login_manager = LoginManager(application)

# CORS configuration
allowed_origins = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000,https://localhost:3000').split(',')
CORS(application, resources={r"/api/*": {"origins": allowed_origins, "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"], "supports_credentials": True}})

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    role = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password_set = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        self.password_set = True

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_token(self, expires_sec=1800):
        s = URLSafeTimedSerializer(application.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id}, salt='password-reset-salt')

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        s = URLSafeTimedSerializer(application.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, salt='password-reset-salt', max_age=expires_sec)['user_id']
        except:
            return None
        return User.query.get(user_id)

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

# Helper functions
def send_email_notification(to_email, subject, content):
    message = Mail(
        from_email=os.environ.get('FROM_EMAIL'),
        to_emails=to_email,
        subject=subject,
        html_content=content
    )
    try:
        logger.info(f"Sending email to {to_email}")
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
        logger.info(f"SendGrid API response: {response.status_code}")
        return response.status_code
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
        return None

def generate_shift_link(shift_date, user_role):
    base_url = os.environ.get('FRONTEND_URL', 'https://d1ozcmsi9wy8ty.cloudfront.net')
    encoded_date = quote(shift_date.isoformat())
    return f"{base_url}/{'manager' if user_role == 'manager' else 'waiter'}-dashboard?date={encoded_date}"



def notify_shift_change(shift, action):
    user = User.query.get(shift.user_id)
    managers = User.query.filter_by(role='manager').all()
    
    user_link = generate_shift_link(shift.date, user.role)
    manager_link = generate_shift_link(shift.date, 'manager')
    
    subject = f"Shift {action.capitalize()}"
    user_content = f"""
    <strong>Hello {user.name},</strong><br>
    A shift has been {action} with the following details:<br>
    Date: {shift.date.strftime('%Y-%m-%d')}<br>
    Time: {shift.start_time.strftime('%H:%M')} - {shift.end_time.strftime('%H:%M')}<br>
    Type: {shift.shift_type}<br>
    Status: {shift.status}<br><br>
    <a href="{user_link}">Click here to view this shift in your calendar</a>
    """
    
    manager_content = f"""
    <strong>Hello,</strong><br>
    A shift has been {action} for {user.name} with the following details:<br>
    Date: {shift.date.strftime('%Y-%m-%d')}<br>
    Time: {shift.start_time.strftime('%H:%M')} - {shift.end_time.strftime('%H:%M')}<br>
    Type: {shift.shift_type}<br>
    Status: {shift.status}<br><br>
    <a href="{manager_link}">Click here to view this shift in the calendar</a>
    """
    
    send_email_notification(user.email, subject, user_content)
    for manager in managers:
        send_email_notification(manager.email, subject, manager_content)

def notify_shift_creation(shift):
    user = User.query.get(shift.user_id)
    managers = User.query.filter_by(role='manager').all()
    
    user_link = generate_shift_link(shift.date, user.role)
    manager_link = generate_shift_link(shift.date, 'manager')
    
    subject = "New Shift Created"
    user_content = f"""
    <strong>Hello {user.name},</strong><br>
    A new shift has been created for you with the following details:<br>
    Date: {shift.date.strftime('%Y-%m-%d')}<br>
    Time: {shift.start_time.strftime('%H:%M')} - {shift.end_time.strftime('%H:%M')}<br>
    Type: {shift.shift_type}<br>
    Status: {shift.status}<br><br>
    <a href="{user_link}">Click here to view this shift in your calendar</a>
    """
    
    manager_content = f"""
    <strong>Hello,</strong><br>
    A new shift has been created for {user.name} with the following details:<br>
    Date: {shift.date.strftime('%Y-%m-%d')}<br>
    Time: {shift.start_time.strftime('%H:%M')} - {shift.end_time.strftime('%H:%M')}<br>
    Type: {shift.shift_type}<br>
    Status: {shift.status}<br><br>
    <a href="{manager_link}">Click here to view this shift in the calendar</a>
    """
    
    user_notification = send_email_notification(user.email, subject, user_content)
    manager_notifications = [send_email_notification(manager.email, subject, manager_content) for manager in managers]
    
    return all([user_notification] + manager_notifications)

def set_password_flag_for_existing_users():
    with application.app_context():
        users = User.query.all()
        for user in users:
            if user.password_hash and not user.password_set:
                user.password_set = True
                print(f"Setting password_set flag for user: {user.email}")
        db.session.commit()
        print("Password flags updated for all users")

# Routes
@application.route('/')
def hello():
    return jsonify({"message": "Carin is moois"}), 200

@application.route('/api/health')
def health_check():
    return jsonify({"status": "healthy"}), 200

@application.route('/api/test-cors', methods=['GET', 'OPTIONS'])
@cross_origin(origins=allowed_origins, supports_credentials=True)
def test_cors():
    return jsonify({"message": "CORS is working"}), 200

# Authentication routes
@application.route('/api/login', methods=['POST', 'OPTIONS'])
@cross_origin(origins=allowed_origins, supports_credentials=True)
def login():
    if request.method == 'OPTIONS':
        return make_response()

    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'message': 'Invalid login data'}), 400

    user = User.query.filter_by(email=data['email']).first()
    
    # Debug logging
    print(f"Login attempt for email: {data['email']}")
    if user:
        print(f"User found. ID: {user.id}, Name: {user.name}, Role: {user.role}, Password set: {user.password_set}")
    else:
        print("User not found")

    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid email or password'}), 401


    login_user(user, remember=data.get('remember', False))
    return jsonify({
        'message': 'Logged in successfully',
        'role': user.role,
        'name': user.name,
        'id': user.id
    }), 200

@application.route('/api/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'})

# User management routes
@application.route('/api/users', methods=['GET', 'POST'])
@login_required
def handle_users():
    if current_user.role != 'manager':
        return jsonify({'message': 'Unauthorized'}), 403
    
    if request.method == 'GET':
        users = User.query.all()
        return jsonify([{
            'id': u.id, 
            'name': u.name, 
            'email': u.email, 
            'role': u.role,
            'password_set': u.password_set
        } for u in users])
    
    elif request.method == 'POST':
        data = request.json
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email already registered'}), 400
        
        new_user = User(email=data['email'], role=data['role'], name=data['name'], password_set=False)
        db.session.add(new_user)
        db.session.commit()
        
        token = new_user.get_reset_token()
        
        subject = "Your New Account"
        content = f"""
        <strong>Hello {new_user.name},</strong><br>
        Your account has been created. Please click the link below to set your password:<br>
        <a href="{os.environ.get('FRONTEND_URL')}/set-password/{token}">Set Your Password</a><br>
        This link will expire in 30 minutes.
        """
        send_email_notification(new_user.email, subject, content)
        
        return jsonify({'message': 'User created successfully and setup email sent', 'id': new_user.id}), 201

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
        db.session.commit()
        return jsonify({'message': 'User updated successfully'})
    
    elif request.method == 'DELETE':
        if Shift.query.filter_by(user_id=user_id).first():
            return jsonify({'message': 'Cannot delete user with associated shifts'}), 400
        
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})

@application.route('/api/users/<int:user_id>/reset_password', methods=['POST'])
@login_required
def admin_reset_user_password(user_id):
    if current_user.role != 'manager':
        return jsonify({'message': 'Unauthorized'}), 403
    
    user = User.query.get_or_404(user_id)
    token = user.get_reset_token()
    
    subject = "Password Reset Request"
    content = f"""
    A password reset has been requested for your account. Please click the link below to reset your password:
    <a href="{os.environ.get('FRONTEND_URL')}/reset-password/{token}">Reset Your Password</a><br>
    This link will expire in 30 minutes.
    If you did not request this, please contact your administrator.
    """
    send_email_notification(user.email, subject, content)
    
    return jsonify({'message': 'Password reset link sent to user'}), 200

@application.route('/api/set_password', methods=['POST'])
def set_password():
    data = request.json
    user = User.verify_reset_token(data['token'])
    if user is None:
        return jsonify({'message': 'Invalid or expired token'}), 400
    
    user.set_password(data['password'])
    db.session.commit()
    
    return jsonify({'message': 'Password set successfully'}), 200

@application.route('/api/reset_password_request', methods=['POST'])
def reset_password_request():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user:
        token = user.get_reset_token()
        subject = "Password Reset Request"
        content = f"""
        To reset your password, visit the following link:
        {os.environ.get('FRONTEND_URL')}/reset-password/{token}
        If you did not make this request then simply ignore this email and no changes will be made.
        """
        send_email_notification(user.email, subject, content)
    return jsonify({'message': 'If an account with that email exists, we have sent a password reset link'}), 200

@application.route('/api/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.json
    user = current_user
    
    if not user.check_password(data['current_password']):
        return jsonify({'message': 'Current password is incorrect'}), 400
    
    user.set_password(data['new_password'])
    db.session.commit()
    
    subject = "Password Changed"
    content = f"""
    <strong>Hello {user.name},</strong><br>
    Your password has been successfully changed. If you did not make this change, please contact the administrator immediately.
    """
    send_email_notification(user.email, subject, content)
    
    return jsonify({'message': 'Password changed successfully'}), 200

@application.route('/api/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    user = User.verify_reset_token(data['token'])
    if user is None:
        return jsonify({'message': 'Invalid or expired token'}), 400
    
    user.set_password(data['password'])
    db.session.commit()
    
    return jsonify({'message': 'Password reset successfully'}), 200

# Shift management routes
@application.route('/api/shifts', methods=['GET', 'POST'])
@login_required
def handle_shifts():
    if request.method == 'GET':
        try:
            shifts = Shift.query.options(joinedload(Shift.user)).all()
            return jsonify([{
                'id': shift.id,
                'user_id': shift.user_id,
                'user_name': shift.user.name,
                'date': shift.date.isoformat(),
                'start_time': shift.start_time.isoformat(),
                'end_time': shift.end_time.isoformat(),
                'status': shift.status,
                'shift_type': shift.shift_type,
            } for shift in shifts]), 200
        except Exception as e:
            logger.error(f"Error fetching shifts: {str(e)}", exc_info=True)
            return jsonify({'message': 'An error occurred while fetching shifts', 'error': str(e)}), 500

    elif request.method == 'POST':
        data = request.json
        user_id = data.get('user_id', current_user.id)
       
        if current_user.role != 'manager' and user_id != current_user.id:
            return jsonify({'message': 'Unauthorized'}), 403
       
        try:
            date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'message': 'Invalid date format. Use YYYY-MM-DD.'}), 400
       
        existing_shift = Shift.query.filter_by(user_id=user_id, date=date).first()
        if existing_shift and current_user.role != 'manager':
            return jsonify({'message': 'You already have a shift on this day'}), 400
       
        try:
            new_shift = Shift(
                user_id=user_id,
                date=date,
                start_time=datetime.strptime(data['start_time'], '%H:%M').time(),
                end_time=datetime.strptime(data['end_time'], '%H:%M').time(),
                shift_type=data['shift_type'],
                status='requested'
            )
            db.session.add(new_shift)
            db.session.commit()

            notification_sent = notify_shift_creation(new_shift)
            if notification_sent:
                return jsonify({'message': 'Shift created successfully and notifications sent', 'id': new_shift.id}), 201
            else:
                return jsonify({'message': 'Shift created successfully but there was an issue sending notifications', 'id': new_shift.id}), 201
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating shift: {str(e)}", exc_info=True)
            return jsonify({'message': 'Failed to create shift', 'error': str(e)}), 500

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
        
        try:
            db.session.commit()
            notify_shift_change(shift, 'updated')
            return jsonify({'message': 'Shift updated successfully'}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating shift: {str(e)}")
            return jsonify({'message': 'Failed to update shift', 'error': str(e)}), 500
   
    elif request.method == 'DELETE':
        try:
            notify_shift_change(shift, 'deleted')
            db.session.delete(shift)
            db.session.commit()
            return jsonify({'message': 'Shift deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting shift: {str(e)}")
            return jsonify({'message': 'Failed to delete shift', 'error': str(e)}), 500

# Database initialization
def init_db():
    with application.app_context():
        db.create_all()
        if not User.query.filter_by(email=os.getenv('ADMIN_EMAIL')).first():
            admin_user = User(
                email=os.getenv('ADMIN_EMAIL'),
                role='manager',
                name='Admin',
                password_set=True
            )
            admin_user.set_password(os.getenv('ADMIN_PASSWORD'))
            db.session.add(admin_user)
            db.session.commit()

init_db()

def create_application(config_object=None):
    app = Flask(__name__)
    
    if config_object:
        app.config.from_object(config_object)
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    
    db.init_app(app)
    login_manager.init_app(app)
    CORS(app)
    
    # Register all routes
   # Register all routes
    app.add_url_rule('/', 'hello', hello)
    app.add_url_rule('/api/health', 'health_check', health_check)
    app.add_url_rule('/api/login', 'login', login, methods=['POST'])
    app.add_url_rule('/api/logout', 'logout', logout)
    app.add_url_rule('/api/users', 'handle_users', handle_users, methods=['GET', 'POST'])
    app.add_url_rule('/api/users/<int:user_id>', 'manage_user', manage_user, methods=['PUT', 'DELETE'])
    app.add_url_rule('/api/shifts', 'handle_shifts', handle_shifts, methods=['GET', 'POST'])
    app.add_url_rule('/api/shifts/<int:shift_id>', 'manage_shift', manage_shift, methods=['PUT', 'DELETE'])
    app.add_url_rule('/api/change_password', 'change_password', change_password, methods=['POST'])
    app.add_url_rule('/api/reset_password', 'reset_password', reset_password, methods=['POST'])
    app.add_url_rule('/api/reset_password_request', 'reset_password_request', reset_password_request, methods=['POST'])
    app.add_url_rule('/api/set_password', 'set_password', set_password, methods=['POST'])
    app.add_url_rule('/api/test-cors', 'test_cors', test_cors, methods=['GET', 'OPTIONS'])
    
    return app

if __name__ == '__main__':
    application = create_application()
    set_password_flag_for_existing_users()
    with application.app_context():
        db.create_all()
        
        # Check if admin user exists, if not, create it
        admin_email = os.getenv('ADMIN_EMAIL')
        admin_password = os.getenv('ADMIN_PASSWORD')
        admin_name = os.getenv('ADMIN_NAME')
        
        if not admin_email or not admin_password or not admin_name:
            print("Error: ADMIN_EMAIL, ADMIN_PASSWORD, and ADMIN_NAME must be set in environment variables.")
        else:
            if not User.query.filter_by(email=admin_email).first():
                admin_user = User(
                    email=admin_email,
                    role='manager',
                    name=admin_name
                )
                admin_user.set_password(admin_password)
                db.session.add(admin_user)
                db.session.commit()
                print(f"Admin user created: {admin_email}")
            else:
                print(f"Admin user already exists: {admin_email}")
    
    application.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), ssl_context='adhoc')