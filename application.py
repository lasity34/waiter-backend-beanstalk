import os
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text

application = Flask(__name__)

# Database configuration
application.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(application)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    role = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@application.route('/')
def hello():
    return jsonify({"message": "Hello, World!"}), 200

@application.route('/env')
def show_env():
    return jsonify({
        "DATABASE_URL": os.getenv('DATABASE_URL', 'Not set'),
        "ADMIN_EMAIL": os.getenv('ADMIN_EMAIL', 'Not set'),
        "ALLOWED_ORIGINS": os.getenv('ALLOWED_ORIGINS', 'Not set'),
        "SECRET_KEY": 'Set' if os.getenv('SECRET_KEY') else 'Not set'
    }), 200

@application.route('/db-test')
def db_test():
    try:
        result = db.session.execute(text('SELECT 1'))
        return jsonify({"message": "Database connection successful", "result": result.scalar()}), 200
    except Exception as e:
        return jsonify({"message": f"Database connection failed: {str(e)}"}), 500

@application.route('/create-tables')
def create_tables():
    try:
        db.create_all()
        return jsonify({"message": "Tables created successfully"}), 200
    except Exception as e:
        return jsonify({"message": f"Failed to create tables: {str(e)}"}), 500

if __name__ == '__main__':
    application.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))