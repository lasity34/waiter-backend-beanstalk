import pytest
from application import create_application, db, User, Shift
from test_config import TestConfig
from datetime import datetime, time

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
        db.create_all()
        
        # Create test users
        admin = User(email='admin@test.com', role='manager', name='Admin')
        admin.set_password('adminpass')
        waiter = User(email='waiter@test.com', role='waiter', name='Waiter')
        waiter.set_password('waiterpass')
        
        # Add users to database
        db.session.add(admin)
        db.session.add(waiter)
        db.session.commit()

        # Create a test shift
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
    return client.post('/api/login', json={
        'email': email,
        'password': password
    })



def test_database_uri(app):
    assert app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///:memory:', \
        "Test is not using in-memory SQLite database"

# The rest of your test functions remain the same
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


# shifts

def test_create_shift_as_waiter(client, init_database):
    login_user(client, 'waiter@test.com', 'waiterpass')
    response = client.post('/api/shifts', json={
        'date': '2023-06-01',
        'start_time': '09:00',
        'end_time': '17:00',
        'shift_type': 'morning'
    })
    assert response.status_code == 201
    assert b'Shift created successfully' in response.data

def test_create_shift_as_manager(client, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
    response = client.post('/api/shifts', json={
        'user_id': 2,  # Assuming waiter's id is 2
        'date': '2023-06-02',
        'start_time': '17:00',
        'end_time': '01:00',
        'shift_type': 'evening'
    })
    assert response.status_code == 201
    assert b'Shift created successfully' in response.data

def test_get_shifts(client, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/shifts')
    assert response.status_code == 200
    shifts = response.get_json()
    assert len(shifts) == 1
    assert shifts[0]['shift_type'] == 'morning'

def test_update_shift(client, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
    # First, get the shift id
    response = client.get('/api/shifts')
    shifts = response.get_json()
    shift_id = shifts[0]['id']
    
    # Now update the shift
    response = client.put(f'/api/shifts/{shift_id}', json={
        'shift_type': 'evening',
        'status': 'approved'
    })
    assert response.status_code == 200
    assert b'Shift updated successfully' in response.data

def test_delete_shift(client, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
    # First, get the shift id
    response = client.get('/api/shifts')
    shifts = response.get_json()
    shift_id = shifts[0]['id']
    
    # Now delete the shift
    response = client.delete(f'/api/shifts/{shift_id}')
    assert response.status_code == 200
    assert b'Shift deleted successfully' in response.data

# users

def test_create_user(client, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
    response = client.post('/api/users', json={
        'email': 'newuser@test.com',
        'password': 'newuserpass',
        'role': 'waiter',
        'name': 'New User'
    })
    assert response.status_code == 201
    assert b'User created successfully' in response.data

def test_get_users(client, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
    response = client.get('/api/users')
    assert response.status_code == 200
    users = response.get_json()
    assert len(users) == 2  # Admin and Waiter

def test_update_user(client, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
    # First, get the waiter's id
    response = client.get('/api/users')
    users = response.get_json()
    waiter_id = [user['id'] for user in users if user['role'] == 'waiter'][0]
    
    # Now update the user
    response = client.put(f'/api/users/{waiter_id}', json={
        'name': 'Updated Waiter Name',
        'role': 'manager'
    })
    assert response.status_code == 200
    assert b'User updated successfully' in response.data

def test_delete_user(client, app, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
   
    # First, get the waiter's id
    response = client.get('/api/users')
    users = response.get_json()
    waiter_id = [user['id'] for user in users if user['role'] == 'waiter'][0]
   
    # Delete all shifts associated with the user
    with app.app_context():
        Shift.query.filter_by(user_id=waiter_id).delete()
        db.session.commit()
   
    # Now delete the user
    response = client.delete(f'/api/users/{waiter_id}')
    assert response.status_code == 200
    assert b'User deleted successfully' in response.data

    # Verify that the user has been deleted
    response = client.get('/api/users')
    users = response.get_json()
    assert len([user for user in users if user['role'] == 'waiter']) == 0

def test_delete_user_with_shifts(client, init_database):
    login_user(client, 'admin@test.com', 'adminpass')
    
    # First, get the waiter's id
    response = client.get('/api/users')
    users = response.get_json()
    waiter_id = [user['id'] for user in users if user['role'] == 'waiter'][0]
    
    # Attempt to delete the user (which should fail due to associated shifts)
    response = client.delete(f'/api/users/{waiter_id}')
    assert response.status_code == 400
    assert b'Cannot delete user with associated shifts' in response.data

    # Verify that the user still exists
    response = client.get('/api/users')
    users = response.get_json()
    assert len([user for user in users if user['role'] == 'waiter']) == 1


def test_unauthorized_access(client, init_database):
    login_user(client, 'waiter@test.com', 'waiterpass')
    response = client.get('/api/users')
    assert response.status_code == 403
    assert b'Unauthorized' in response.data

def test_create_duplicate_shift(client, init_database):
    login_user(client, 'waiter@test.com', 'waiterpass')
    # Create first shift
    client.post('/api/shifts', json={
        'date': '2023-06-01',
        'start_time': '09:00',
        'end_time': '17:00',
        'shift_type': 'morning'
    })
    # Try to create another shift on the same day
    response = client.post('/api/shifts', json={
        'date': '2023-06-01',
        'start_time': '17:00',
        'end_time': '01:00',
        'shift_type': 'evening'
    })
    assert response.status_code == 400
    assert b'You already have a shift on this day' in response.data
# Add more tests as needed