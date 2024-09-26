import pytest
from application import create_application, db, User, Shift, notify_shift_change, send_email_notification, notify_shift_creation
from test_config import TestConfig
from datetime import datetime, time
import logging

@pytest.fixture(scope='module')
def app():
    app = create_application(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture(scope='module')
def client(app):
    return app.test_client()

@pytest.fixture(scope='function')
def init_database(app):
    with app.app_context():
        db.drop_all()  # Drop all tables
        db.create_all()  # Recreate all tables
        
        # Create and commit users
        admin = User(email='admin@test.com', role='manager', name='Admin', password_set=True)
        admin.set_password('adminpass')
        waiter = User(email='waiter@test.com', role='waiter', name='Waiter', password_set=True)
        waiter.set_password('waiterpass')
        db.session.add_all([admin, waiter])
        db.session.commit()

        # Create shift
        shift = Shift(
            user_id=waiter.id,
            date=datetime.now().date(),
            start_time=time(9, 0),
            end_time=time(17, 0),
            status='requested',
            shift_type='morning'
        )
        db.session.add(shift)
        db.session.commit()

        yield

        db.session.remove()
        db.drop_all()

def login_user(client, email, password):
    response = client.post('/api/login', json={'email': email, 'password': password})
    if response.status_code == 200:
        return response, response.json['auth_token']
    return response, None

def add_auth_token(headers, token):
    if token:
        headers['Authorization'] = token
    return headers

# Configuration tests
def test_database_uri(app):
    assert app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///:memory:', \
        "Test is not using in-memory SQLite database"

# Authentication tests
def test_login_success(client, init_database):
    response, token = login_user(client, 'admin@test.com', 'adminpass')
    assert response.status_code == 200
    assert 'Logged in successfully' in response.json['message']
    assert token is not None

def test_login_failure(client, init_database):
    response, token = login_user(client, 'admin@test.com', 'wrongpass')
    assert response.status_code == 401
    assert 'Invalid email or password' in response.json['message']
    assert token is None

def test_logout(client, init_database):
    _, token = login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/logout', headers=add_auth_token({}, token))
    assert response.status_code == 200
    assert b'Logged out successfully' in response.data


def test_create_user(client, init_database, mocker):
    _, token = login_user(client, 'admin@test.com', 'adminpass')
    mock_send_email = mocker.patch('application.send_email_notification')
    response = client.post('/api/users', 
                           json={
                               'email': 'newuser@test.com',
                               'role': 'waiter',
                               'name': 'New User'
                           },
                           headers=add_auth_token({}, token))
    assert response.status_code == 201
    assert b'User created successfully' in response.data
    mock_send_email.assert_called_once()


def test_get_users(client, init_database):
    _, token = login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/users', headers=add_auth_token({}, token))
    assert response.status_code == 200
    users = response.get_json()
    assert len(users) == 2

def test_update_user(client, init_database):
    _, token = login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/users', headers=add_auth_token({}, token))
    users = response.get_json()
    waiter_id = [user['id'] for user in users if user['role'] == 'waiter'][0]
    response = client.put(f'/api/users/{waiter_id}', 
                          json={
                              'name': 'Updated Waiter Name',
                              'role': 'manager'
                          },
                          headers=add_auth_token({}, token))
    assert response.status_code == 200
    assert b'User updated successfully' in response.data


def test_delete_user(client, app, init_database):
    _, token = login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/users', headers=add_auth_token({}, token))
    users = response.get_json()
    waiter_id = [user['id'] for user in users if user['role'] == 'waiter'][0]
    with app.app_context():
        Shift.query.filter_by(user_id=waiter_id).delete()
        db.session.commit()
    response = client.delete(f'/api/users/{waiter_id}', headers=add_auth_token({}, token))
    assert response.status_code == 200
    assert b'User deleted successfully' in response.data
    response = client.get('/api/users', headers=add_auth_token({}, token))
    users = response.get_json()
    assert len([user for user in users if user['role'] == 'waiter']) == 0



def test_delete_user_with_shifts(client, init_database):
    _, token = login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/users', headers=add_auth_token({}, token))
    users = response.json
    waiter_id = [user['id'] for user in users if user['role'] == 'waiter'][0]
    response = client.delete(f'/api/users/{waiter_id}', headers=add_auth_token({}, token))
    assert response.status_code == 400
    assert b'Cannot delete user with associated shifts' in response.data
    response = client.get('/api/users', headers=add_auth_token({}, token))
    users = response.json
    assert len([user for user in users if user['role'] == 'waiter']) == 1

def test_unauthorized_access(client, init_database):
    _, token = login_user(client, 'waiter@test.com', 'waiterpass')
    response = client.get('/api/users', headers=add_auth_token({}, token))
    assert response.status_code == 403
    assert b'Unauthorized' in response.data

# Password management tests
def test_change_password(client, init_database, mocker):
    _, token = login_user(client, 'waiter@test.com', 'waiterpass')
    mock_send_email = mocker.patch('application.send_email_notification')
    response = client.post('/api/change_password', 
                           json={
                               'current_password': 'waiterpass',
                               'new_password': 'newwaiterpass'
                           },
                           headers=add_auth_token({}, token))
    assert response.status_code == 200
    assert b'Password changed successfully' in response.data
    mock_send_email.assert_called_once()

    # Verify the user can now log in with the new password
    logout_response = client.get('/api/logout', headers=add_auth_token({}, token))
    assert logout_response.status_code == 200

    login_response, _ = login_user(client, 'waiter@test.com', 'newwaiterpass')
    assert login_response.status_code == 200
    assert b'Logged in successfully' in login_response.data

def test_reset_password(client, init_database):
    # First, get a valid token
    with client.application.app_context():
        user = User.query.filter_by(email='waiter@test.com').first()
        token = user.get_reset_token()

    response = client.post('/api/reset_password', json={
        'token': token,
        'password': 'newwaiterpass123'
    })
    assert response.status_code == 200
    assert b'Password reset successfully' in response.data

    # Verify the user can now log in with the new password
    login_response, _ = login_user(client, 'waiter@test.com', 'newwaiterpass123')
    assert login_response.status_code == 200
    assert b'Logged in successfully' in login_response.data

def test_set_password(client, init_database, mocker):
    # First, create a user without a password
    user = User(email='nopassword@test.com', role='waiter', name='No Password User', password_set=False)
    with client.application.app_context():
        db.session.add(user)
        db.session.commit()
        token = user.get_reset_token()

    response = client.post('/api/set_password', json={
        'token': token,
        'password': 'newpassword123'
    })
    assert response.status_code == 200
    assert b'Password set successfully' in response.data

    # Verify the user can now log in
    login_response, _ = login_user(client, 'nopassword@test.com', 'newpassword123')
    assert login_response.status_code == 200
    assert b'Logged in successfully' in login_response.data

def test_set_password_invalid_token(client, init_database):
    response = client.post('/api/set_password', json={
        'token': 'invalid_token',
        'password': 'newpassword123'
    })
    assert response.status_code == 400
    assert b'Invalid or expired token' in response.data

def test_reset_password_request(client, init_database, mocker):
    mock_send_email = mocker.patch('application.send_email_notification')
    response = client.post('/api/reset_password_request', json={
        'email': 'waiter@test.com'
    })
    assert response.status_code == 200
    assert b'If an account with that email exists, we have sent a password reset link' in response.data
    mock_send_email.assert_called_once()

def test_reset_password_request_nonexistent_email(client, init_database, mocker):
    mock_send_email = mocker.patch('application.send_email_notification')
    response = client.post('/api/reset_password_request', json={
        'email': 'nonexistent@test.com'
    })
    assert response.status_code == 200  # We return 200 even for non-existent emails for security reasons
    assert b'If an account with that email exists, we have sent a password reset link' in response.data
    mock_send_email.assert_not_called()

# Update the test_reset_password function
def test_reset_password(client, init_database):
    # First, get a valid token
    with client.application.app_context():
        user = User.query.filter_by(email='waiter@test.com').first()
        token = user.get_reset_token()

    response = client.post('/api/reset_password', json={
        'token': token,
        'password': 'newwaiterpass123'
    })
    assert response.status_code == 200
    assert b'Password reset successfully' in response.data

    # Verify the user can now log in with the new password
    login_response, _ = login_user(client, 'waiter@test.com', 'newwaiterpass123')
    assert login_response.status_code == 200
    assert b'Logged in successfully' in login_response.data

# Shift management tests
def test_create_shift_as_waiter(client, init_database, mocker):
    _, token = login_user(client, 'waiter@test.com', 'waiterpass')
    mock_send_email = mocker.patch('application.send_email_notification')
    response = client.post('/api/shifts', 
                           json={
                               'date': '2023-06-01',
                               'start_time': '09:00',
                               'end_time': '17:00',
                               'shift_type': 'morning'
                           },
                           headers=add_auth_token({}, token))
    assert response.status_code == 201
    assert b'Shift created successfully' in response.data
    assert mock_send_email.call_count >= 2

def test_create_shift_as_manager(client, init_database, mocker):
    _, token = login_user(client, 'admin@test.com', 'adminpass')
    mock_send_email = mocker.patch('application.send_email_notification')
    response = client.post('/api/shifts', 
                           json={
                               'user_id': 2,  # Assuming waiter's id is 2
                               'date': '2023-06-02',
                               'start_time': '17:00',
                               'end_time': '01:00',
                               'shift_type': 'evening'
                           },
                           headers=add_auth_token({}, token))
    assert response.status_code == 201
    assert b'Shift created successfully' in response.data
    assert mock_send_email.call_count >= 2

def test_get_shifts(client, init_database):
    _, token = login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/shifts', headers=add_auth_token({}, token))
    assert response.status_code == 200
    shifts = response.get_json()
    assert len(shifts) == 1
    assert shifts[0]['shift_type'] == 'morning'

def test_update_shift(client, init_database, mocker):
    _, token = login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/shifts', headers=add_auth_token({}, token))
    shifts = response.get_json()
    shift_id = shifts[0]['id']
    mock_notify = mocker.patch('application.notify_shift_change')
    response = client.put(f'/api/shifts/{shift_id}', 
                          json={
                              'shift_type': 'evening',
                              'status': 'approved'
                          },
                          headers=add_auth_token({}, token))
    assert response.status_code == 200
    assert b'Shift updated successfully' in response.data
    mock_notify.assert_called_once()

def test_delete_shift(client, init_database, mocker):
    _, token = login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/shifts', headers=add_auth_token({}, token))
    shifts = response.get_json()
    shift_id = shifts[0]['id']
    mock_notify = mocker.patch('application.notify_shift_change')
    response = client.delete(f'/api/shifts/{shift_id}', headers=add_auth_token({}, token))
    assert response.status_code == 200
    assert b'Shift deleted successfully' in response.data
    mock_notify.assert_called_once()

def test_create_duplicate_shift(client, init_database):
    _, token = login_user(client, 'waiter@test.com', 'waiterpass')
    client.post('/api/shifts', 
                json={
                    'date': '2023-06-01',
                    'start_time': '09:00',
                    'end_time': '17:00',
                    'shift_type': 'morning'
                },
                headers=add_auth_token({}, token))
    response = client.post('/api/shifts', 
                           json={
                               'date': '2023-06-01',
                               'start_time': '17:00',
                               'end_time': '01:00',
                               'shift_type': 'evening'
                           },
                           headers=add_auth_token({}, token))
    assert response.status_code == 400
    assert b'You already have a shift on this day' in response.data

# Notification tests
def test_send_email_notification(app, mocker):
    with app.app_context():
        mock_sendgrid = mocker.patch('application.SendGridAPIClient')
        mock_sendgrid.return_value.send.return_value.status_code = 202
        status_code = send_email_notification(
            'test@example.com',
            'Test Subject',
            '<strong>Test Content</strong>'
        )
        assert status_code == 202
        mock_sendgrid.assert_called_once()
        mock_sendgrid.return_value.send.assert_called_once()

def test_notify_shift_change(app, init_database, mocker):
    with app.app_context():
        user = User.query.filter_by(email='waiter@test.com').first()
        assert user is not None, "User not found in the database"
        shift = Shift(
            user_id=user.id,
            date=datetime(2023, 6, 1).date(),
            start_time=datetime(2023, 6, 1, 9, 0).time(),
            end_time=datetime(2023, 6, 1, 17, 0).time(),
            shift_type='morning',
            status='approved'
        )
        db.session.add(shift)
        db.session.commit()
        mock_send_email = mocker.patch('application.send_email_notification')
        mock_send_email.return_value = 202
        notify_shift_change(shift, 'updated')
        assert mock_send_email.call_count == 2
        db.session.delete(shift)
        db.session.commit()

def test_notify_shift_creation(app, init_database, mocker):
    with app.app_context():
        waiter = User.query.filter_by(email='waiter@test.com').first()
        assert waiter is not None, "Waiter not found in the database"
        shift = Shift(
            user_id=waiter.id,
            date=datetime(2023, 6, 1).date(),
            start_time=datetime(2023, 6, 1, 9, 0).time(),
            end_time=datetime(2023, 6, 1, 17, 0).time(),
            shift_type='morning',
            status='requested'
        )
        db.session.add(shift)
        db.session.commit()

        # Mock the send_email_notification function
        mock_send_email = mocker.patch('application.send_email_notification')
        mock_send_email.return_value = 202  # Simulate successful email sending

        # Call the function we're testing
        result = notify_shift_creation(shift)

        # Assert that the function returned True (all notifications sent successfully)
        assert result is True

        # Check that send_email_notification was called at least twice
        assert mock_send_email.call_count >= 2

        db.session.delete(shift)
        db.session.commit()

        
def test_reset_password_invalid_token(client, init_database):
    response = client.post('/api/reset_password', json={
        'token': 'invalid_token',
        'password': 'newpassword123'
    })
    assert response.status_code == 400
    assert b'Invalid or expired token' in response.data