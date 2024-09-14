from flask import Flask

application = Flask(__name__)

@application.route('/')
def hello():
    return "Hello World! Welcome to the Waiter Scheduling App."

if __name__ == "__main__":
    application.run(host='0.0.0.0', port=5000)