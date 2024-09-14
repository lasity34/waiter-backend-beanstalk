import os
from flask import Flask, jsonify

application = Flask(__name__)

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

if __name__ == '__main__':
    application.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))