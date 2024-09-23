class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'test_secret_key'
    
    # Test-specific configurations
    ADMIN_EMAIL = 'test_admin@example.com'
    ADMIN_PASSWORD = 'test_password'