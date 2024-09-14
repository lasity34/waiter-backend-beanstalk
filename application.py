import os
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy

application = Flask(__name__)

# Database configuration
application.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(application)

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
        db.session.execute('SELECT 1')
        return jsonify({"message": "Database connection successful"}), 200
    except Exception as e:
        return jsonify({"message": f"Database connection failed: {str(e)}"}), 500

if __name__ == '__main__':
    application.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))