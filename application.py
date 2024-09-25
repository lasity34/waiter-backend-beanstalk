import os
import logging
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy.orm import joinedload
from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# Load the .env file from the current directory
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
application = Flask(__name__)
logger.info("Flask app initialized")

allowed_origins = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000,https://localhost:3000').split(',')

CORS(application, resources={r"/api/*": {
    "origins": allowed_origins,
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"],
    "supports_credentials": True
}})


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




# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    role = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=False)

    def set_password(self, password):
        logger.info(f"Setting new password for user: {self.email}")
        self.password_hash = generate_password_hash(password)
        logger.info(f"New password hash generated for user: {self.email}")

    def check_password(self, password):
        logger.info(f"Checking password for user: {self.email}")
        result = check_password_hash(self.password_hash, password)
        logger.info(f"Password check result for user {self.email}: {'Success' if result else 'Failure'}")
        return result

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
    return jsonify({"message": "Carin is moois"}), 200

@application.route('/api/health')
def health_check():
    return jsonify({"status": "healthy"}), 200

@application.route('/api/test-cors', methods=['GET', 'OPTIONS'])
@cross_origin(origins=allowed_origins, supports_credentials=True)
def test_cors():
    return jsonify({"message": "CORS is working"}), 200


@application.route('/api/login', methods=['POST', 'OPTIONS'])
@cross_origin(origins=allowed_origins, supports_credentials=True)
def login():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    logger.info("Login attempt received")
    logger.info(f"Request method: {request.method}")
    logger.info(f"Request headers: {request.headers}")
    logger.info(f"Request data: {request.data}")
   
    try:
        data = request.get_json()
        logger.info(f"Parsed JSON data: {data}")
       
        if not data or 'email' not in data or 'password' not in data:
            logger.warning("Invalid login data received")
            return jsonify({'message': 'Invalid login data'}), 400
       
        user = User.query.filter_by(email=data['email']).first()
       
        if not user:
            logger.warning(f"No user found for email: {data['email']}")
            return jsonify({'message': 'Invalid email or password'}), 401
       
        if not user.check_password(data['password']):
            logger.warning(f"Incorrect password for email: {data['email']}")
            return jsonify({'message': 'Invalid email or password'}), 401
       
        login_user(user, remember=data.get('remember', False))
        logger.info(f"Login successful for user: {user.email}")
        
        response = jsonify({
            'message': 'Logged in successfully',
            'role': user.role,
            'name': user.name,
            'id': user.id
        })
        return response, 200
    except Exception as e:
        logger.error(f"Exception in login route: {str(e)}", exc_info=True)
        return jsonify({'message': 'An error occurred during login'}), 500
    

@application.route('/api/update_password_hashes', methods=['POST'])
def update_password_hashes():
    users = User.query.all()
    for user in users:
        # Set a temporary password for all users
        user.set_password('temp_password')
    db.session.commit()
    return jsonify({'message': 'All user passwords updated to temporary password'})


@application.route('/api/update_user_password', methods=['POST'])
def update_user_password():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404
    user.set_password(data['new_password'])
    db.session.commit()
    return jsonify({'message': 'Password updated successfully'})


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
        
        # Send email notification
        subject = "Your New Account"
        content = f"""
        <strong>Hello {new_user.name},</strong><br>
        Your account has been created with the following details:<br>
        Email: {new_user.email}<br>
        Please log in to your account and change your password.
        """
        send_email_notification(new_user.email, subject, content)
        
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
        # Check if the user has any associated shifts
        if Shift.query.filter_by(user_id=user_id).first():
            return jsonify({'message': 'Cannot delete user with associated shifts'}), 400
        
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})
    
# test

@application.route('/api/check_users', methods=['GET'])
def check_users():
    users = User.query.all()
    user_info = [{
        'email': user.email,
        'role': user.role,
        'password_hash': user.password_hash[:20] + '...'  # Only show part of the hash for security
    } for user in users]
    return jsonify(user_info)


# notifications

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
    

def notify_shift_change(shift, action):
    user = User.query.get(shift.user_id)
    managers = User.query.filter_by(role='manager').all()
    
    subject = f"Shift {action.capitalize()}"
    content = f"""
    <strong>Hello,</strong><br>
    A shift has been {action} with the following details:<br>
    User: {user.name}<br>
    Date: {shift.date.strftime('%Y-%m-%d')}<br>
    Time: {shift.start_time.strftime('%H:%M')} - {shift.end_time.strftime('%H:%M')}<br>
    Type: {shift.shift_type}<br>
    Status: {shift.status}
    """
    
    # Notify the user
    send_email_notification(user.email, subject, content)
    
    # Notify all managers
    for manager in managers:
        send_email_notification(manager.email, subject, content)


def notify_shift_creation(shift):
    user = User.query.get(shift.user_id)
    managers = User.query.filter_by(role='manager').all()
    
    subject = "New Shift Created"
    content = f"""
    <strong>Hello,</strong><br>
    A new shift has been created with the following details:<br>
    Waiter: {user.name}<br>
    Date: {shift.date.strftime('%Y-%m-%d')}<br>
    Time: {shift.start_time.strftime('%H:%M')} - {shift.end_time.strftime('%H:%M')}<br>
    Type: {shift.shift_type}<br>
    Status: {shift.status}
    """
    
    # Notify the waiter
    logger.info(f"Attempting to send email to waiter: {user.email}")
    waiter_notification = send_email_notification(user.email, subject, content)
    logger.info(f"Email sent to waiter. Result: {waiter_notification}")
    
    # Notify all managers
    manager_notifications = []
    for manager in managers:
        logger.info(f"Attempting to send email to manager: {manager.email}")
        result = send_email_notification(manager.email, subject, content)
        logger.info(f"Email sent to manager. Result: {result}")
        manager_notifications.append(result)
    
    all_notifications_sent = all([waiter_notification] + manager_notifications)
    logger.info(f"All notifications sent successfully: {all_notifications_sent}")
    
    return all_notifications_sent



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
            status='requested'
        )
        db.session.add(new_shift)
       
        try:
            db.session.commit()
            # Send notification for shift creation
            notification_sent = notify_shift_creation(new_shift)
            if notification_sent:
                return jsonify({'message': 'Shift created successfully and notifications sent', 'id': new_shift.id}), 201
            else:
                return jsonify({'message': 'Shift created successfully but there was an issue sending notifications', 'id': new_shift.id}), 201
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating shift: {str(e)}")
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
            # Send notification for shift update
            notify_shift_change(shift, 'updated')
            return jsonify({'message': 'Shift updated successfully'}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating shift: {str(e)}")
            return jsonify({'message': 'Failed to update shift', 'error': str(e)}), 500
   
    elif request.method == 'DELETE':
        try:
            # Send notification before deleting the shift
            notify_shift_change(shift, 'deleted')
            db.session.delete(shift)
            db.session.commit()
            return jsonify({'message': 'Shift deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting shift: {str(e)}")
            return jsonify({'message': 'Failed to delete shift', 'error': str(e)}), 500

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


def create_application(config_object=None):
    app = Flask(__name__)
    
    if config_object:
        app.config.from_object(config_object)
    else:
        # Load the default configuration
        app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    CORS(app)
    
    # Register all routes
    app.add_url_rule('/', 'hello', hello)
    app.add_url_rule('/api/health', 'health_check', health_check)
    app.add_url_rule('/api/login', 'login', login, methods=['POST'])
    app.add_url_rule('/api/logout', 'logout', logout)
    app.add_url_rule('/api/users', 'handle_users', handle_users, methods=['GET', 'POST'])
    app.add_url_rule('/api/users/<int:user_id>', 'manage_user', manage_user, methods=['PUT', 'DELETE'])
    app.add_url_rule('/api/shifts', 'handle_shifts', handle_shifts, methods=['GET', 'POST'])
    app.add_url_rule('/api/shifts/<int:shift_id>', 'manage_shift', manage_shift, methods=['PUT', 'DELETE'])
    app.add_url_rule('/api/check_users', 'check_users', check_users)
    app.add_url_rule('/api/test-cors', 'test_cors', test_cors, methods=['GET', 'OPTIONS'])
    
    return app

if __name__ == '__main__':
    application = create_application()
    
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