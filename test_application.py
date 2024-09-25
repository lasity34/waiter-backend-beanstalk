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
        try:
            db.create_all()
            
            # Create and commit users first
            admin = User(email='admin@test.com', role='manager', name='Admin')
            admin.set_password('adminpass')
            waiter = User(email='waiter@test.com', role='waiter', name='Waiter')
            waiter.set_password('waiterpass')
            db.session.add_all([admin, waiter])
            db.session.commit()  # Commit to ensure users have IDs

            # Now create the shift
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

        except Exception as e:
            logging.error(f"Error setting up test database: {str(e)}")
            raise

        finally:
            db.session.remove()
            db.drop_all()

def login_user(client, email, password):
    return client.post('/api/login', json={'email': email, 'password': password})

# Configuration tests
def test_database_uri(app):
    assert app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///:memory:', \
        "Test is not using in-memory SQLite database"

# Authentication tests
def test_login_success(client, init_database):
    response = login_user(client, 'admin@test.com', 'adminpass')
    assert response.status_code == 200
    assert b'Logged in successfully' in response.data

def test_login_failure(client, init_database):
    response = login_user(client, 'admin@test.com', 'wrongpass')
    assert response.status_code == 401
    assert b'Invalid email or password' in response.data

def test_logout(client, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/logout')
    assert response.status_code == 200
    assert b'Logged out successfully' in response.data

# User management tests
def test_create_user(client, init_database, mocker):
    login_user(client, 'admin@test.com', 'adminpass')
    mock_send_email = mocker.patch('application.send_email_notification')
    response = client.post('/api/users', json={
        'email': 'newuser@test.com',
        'role': 'waiter',
        'name': 'New User'
    })
    assert response.status_code == 201
    assert b'User created successfully' in response.data
    mock_send_email.assert_called_once()

def test_get_users(client, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/users')
    assert response.status_code == 200
    users = response.get_json()
    assert len(users) == 2

def test_update_user(client, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/users')
    users = response.get_json()
    waiter_id = [user['id'] for user in users if user['role'] == 'waiter'][0]
    response = client.put(f'/api/users/{waiter_id}', json={
        'name': 'Updated Waiter Name',
        'role': 'manager'
    })
    assert response.status_code == 200
    assert b'User updated successfully' in response.data

def test_delete_user(client, app, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/users')
    users = response.get_json()
    waiter_id = [user['id'] for user in users if user['role'] == 'waiter'][0]
    with app.app_context():
        Shift.query.filter_by(user_id=waiter_id).delete()
        db.session.commit()
    response = client.delete(f'/api/users/{waiter_id}')
    assert response.status_code == 200
    assert b'User deleted successfully' in response.data
    response = client.get('/api/users')
    users = response.get_json()
    assert len([user for user in users if user['role'] == 'waiter']) == 0

def test_delete_user_with_shifts(client, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/users')
    users = response.get_json()
    waiter_id = [user['id'] for user in users if user['role'] == 'waiter'][0]
    response = client.delete(f'/api/users/{waiter_id}')
    assert response.status_code == 400
    assert b'Cannot delete user with associated shifts' in response.data
    response = client.get('/api/users')
    users = response.get_json()
    assert len([user for user in users if user['role'] == 'waiter']) == 1

def test_unauthorized_access(client, init_database):
    login_user(client, 'waiter@test.com', 'waiterpass')
    response = client.get('/api/users')
    assert response.status_code == 403
    assert b'Unauthorized' in response.data

# Password management tests
def test_change_password(client, init_database, mocker):
    login_user(client, 'waiter@test.com', 'waiterpass')
    mock_send_email = mocker.patch('application.send_email_notification')
    response = client.post('/api/change_password', json={
        'current_password': 'waiterpass',
        'new_password': 'newwaiterpass'
    })
    assert response.status_code == 200
    assert b'Password changed successfully' in response.data
    mock_send_email.assert_called_once()

def test_reset_password(client, init_database, mocker):
    login_user(client, 'admin@test.com', 'adminpass')
    mock_send_email = mocker.patch('application.send_email_notification')
    response = client.post('/api/reset_password', json={
        'email': 'waiter@test.com'
    })
    assert response.status_code == 200
    assert b'Password reset successfully' in response.data
    mock_send_email.assert_called_once()

# Shift management tests
def test_create_shift_as_waiter(client, init_database, mocker):
    login_user(client, 'waiter@test.com', 'waiterpass')
    mock_send_email = mocker.patch('application.send_email_notification')
    response = client.post('/api/shifts', json={
        'date': '2023-06-01',
        'start_time': '09:00',
        'end_time': '17:00',
        'shift_type': 'morning'
    })
    assert response.status_code == 201
    assert b'Shift created successfully' in response.data
    assert mock_send_email.call_count >= 2

def test_create_shift_as_manager(client, init_database, mocker):
    login_user(client, 'admin@test.com', 'adminpass')
    mock_send_email = mocker.patch('application.send_email_notification')
    response = client.post('/api/shifts', json={
        'user_id': 2,  # Assuming waiter's id is 2
        'date': '2023-06-02',
        'start_time': '17:00',
        'end_time': '01:00',
        'shift_type': 'evening'
    })
    assert response.status_code == 201
    assert b'Shift created successfully' in response.data
    assert mock_send_email.call_count >= 2

def test_get_shifts(client, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/shifts')
    assert response.status_code == 200
    shifts = response.get_json()
    assert len(shifts) == 1
    assert shifts[0]['shift_type'] == 'morning'

def test_update_shift(client, init_database, mocker):
    login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/shifts')
    shifts = response.get_json()
    shift_id = shifts[0]['id']
    mock_notify = mocker.patch('application.notify_shift_change')
    response = client.put(f'/api/shifts/{shift_id}', json={
        'shift_type': 'evening',
        'status': 'approved'
    })
    assert response.status_code == 200
    assert b'Shift updated successfully' in response.data
    mock_notify.assert_called_once()

def test_delete_shift(client, init_database, mocker):
    login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/shifts')
    shifts = response.get_json()
    shift_id = shifts[0]['id']
    mock_notify = mocker.patch('application.notify_shift_change')
    response = client.delete(f'/api/shifts/{shift_id}')
    assert response.status_code == 200
    assert b'Shift deleted successfully' in response.data
    mock_notify.assert_called_once()

def test_create_duplicate_shift(client, init_database):
    login_user(client, 'waiter@test.com', 'waiterpass')
    client.post('/api/shifts', json={
        'date': '2023-06-01',
        'start_time': '09:00',
        'end_time': '17:00',
        'shift_type': 'morning'
    })
    response = client.post('/api/shifts', json={
        'date': '2023-06-01',
        'start_time': '17:00',
        'end_time': '01:00',
        'shift_type': 'evening'
    })
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
        mock_send_email = mocker.patch('application.send_email_notification')
        notify_shift_creation(shift)
        assert mock_send_email.call_count >= 2
        db.session.delete(shift)
        db.session.commit()