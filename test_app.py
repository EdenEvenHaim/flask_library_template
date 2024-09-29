import unittest
from app import app, db, User, Book, Loan  # Adjust your import path if necessary
from flask import jsonify
from flask_jwt_extended import create_access_token

class FlaskTestCase(unittest.TestCase):
    
    def setUp(self):
        """Set up a temporary database and initialize the app."""
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test_library.db'  # Use a separate test database
        app.config['JWT_SECRET_KEY'] = 'your_test_jwt_secret_key'
        self.app = app.test_client()
        db.create_all()

    def tearDown(self):
        """Clean up after each test."""
        db.session.remove()
        db.drop_all()

    def test_register_user(self):
        """Test the user registration route."""
        response = self.app.post('/register', json={
            'username': 'testuser',
            'password': 'password123',
            'email': 'testuser@example.com'
        })
        self.assertEqual(response.status_code, 201)
        self.assertIn(b'User registered successfully', response.data)

    def test_login(self):
        """Test the user login route."""
        # First, register a user
        self.app.post('/register', json={
            'username': 'testuser',
            'password': 'password123',
            'email': 'testuser@example.com'
        })
        # Then, login with the same user credentials
        response = self.app.post('/login', json={
            'username': 'testuser',
            'password': 'password123'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'token', response.data)

    def test_view_books(self):
        """Test viewing books (JWT required)."""
        # Add an admin user and generate a JWT token
        self.app.post('/register', json={
            'username': 'admin',
            'password': 'adminpass',
            'email': 'admin@example.com',
            'role': 'admin'
        })
        token_response = self.app.post('/login', json={
            'username': 'admin',
            'password': 'adminpass'
        })
        token = token_response.get_json()['token']
        
        headers = {
            'Authorization': f'Bearer {token}'
        }
        
        # Add a book to the database
        self.app.post('/books', json={
            'name': 'Test Book',
            'author': 'Test Author',
            'year_published': 2020,
            'type': 'LOAN_10_DAYS'
        }, headers=headers)
        
        # Now test viewing the books
        response = self.app.get('/books', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Test Book', response.data)

if __name__ == '__main__':
    unittest.main()
