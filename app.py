from flask import Flask, logging, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from flask_cors import CORS
from enum import Enum
from logger import setup_logger

# Initialize the app, database, bcrypt, and JWT
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = "123"
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

jwt = JWTManager(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app)  # Enable CORS for all routes
setup_logger(app)

# ENUM for book type (for loans)
class BookType(Enum):
    LOAN_10_DAYS = 1
    LOAN_5_DAYS = 2
    LOAN_2_DAYS = 3

# Models #
# 1. Books Model
class Book(db.Model):
    __tablename__ = 'books'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    year_published = db.Column(db.Integer, nullable=False)
    type = db.Column(db.Enum(BookType), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'available' or 'loaned'
    max_loan_days = db.Column(db.Integer, nullable=False)
    loans = db.relationship('Loan', backref='book', lazy=True)

    def __init__(self, name, author, year_published, type, max_loan_days):
        self.name = name
        self.author = author
        self.year_published = year_published
        self.type = self.convert_type_to_enum(type)
        self.status = 'available'
        self.max_loan_days = max_loan_days

    def convert_type_to_enum(self, type):
        if type == 1:
            return BookType.LOAN_10_DAYS
        elif type == 2:
            return BookType.LOAN_5_DAYS
        elif type == 3:
            return BookType.LOAN_2_DAYS

# 2. Users Model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20), nullable=False)  # 'admin' or 'customer'
    username = db.Column(db.String(50), nullable=False, unique=True)
    city = db.Column(db.String(100))
    age = db.Column(db.Integer)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'active' or 'non-active'
    loans = db.relationship('Loan', backref='user', lazy=True)

# 3. Loans Model (ensure Loan is defined elsewhere if not provided)
class Loan(db.Model):
    __tablename__ = 'loans'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False)
    loan_date = db.Column(db.DateTime, default=datetime.utcnow)
    return_date = db.Column(db.DateTime, nullable=True)

# Routes
# register #
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Validate required fields
    if not data.get('username') or not data.get('password') or not data.get('email'):
        return jsonify({'message': 'Username, password, and email are required'}), 400

    # Check if username or email already exists
    existing_user = User.query.filter((User.username == data['username']) | (User.email == data['email'])).first()
    if existing_user:
        return jsonify({'message': 'Username or email already exists'}), 400

    try:
        # Hash the password
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

        # Set role based on input, default is 'customer'
        user_role = data.get('role', 'admin')  # Admin role can also be passed in the request

        # Create new user
        new_user = User(
            role=user_role,
            username=data['username'],
            city=data.get('city'),
            age=data.get('age'),
            email=data['email'],
            password=hashed_password,
            status='active'  # Default status is 'active'
        )

        # Add and commit the new user to the database
        db.session.add(new_user)
        db.session.commit()

        app.logger.info(f'Registration attempt for username: {new_user.username}')
        return jsonify({'message': 'User registered successfully!', 'role': user_role}), 201

    except Exception as e:
        db.session.rollback()  # Rollback in case of any error
        return jsonify({'message': 'Error registering user', 'error': str(e)}), 500

def get_all():
    """ Custom function to get all request data. """
    return request.get_json()  # You can modify this if you need a different format

@app.route('/login', methods=['POST'])
def login():
    data = get_all()

    # Validate input data
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Missing username or password'}), 400

    # Print the received user data
    print(f'Received username: {data["username"]}')  # Print the username

    # Retrieve user from the database
    user = User.query.filter_by(username=data['username']).first()

    if user:
        # Print user information if found
        print(f'User found: {user.username}')  # Print the found user's username

        # Check the hashed password
        if bcrypt.check_password_hash(user.password, data['password']):
            # Create access token using the user's ID
            access_token = create_access_token(identity=user.username)

            # Print the generated access token
            print(f'Access token generated for user {user.username}: {access_token}')  # Print the token

            return jsonify(token=access_token), 200
        else:
            print(f'Invalid password for user {user.username}.')  # Print invalid password attempt
            return jsonify({'message': 'Invalid credentials'}), 401
    else:
        print(f'No user found with username {data["username"]}.')  # Print user not found
        return jsonify({'message': 'Invalid credentials'}), 401

# CRUD #
# Add a new customer
@app.route('/customers', methods=['POST'])
@jwt_required()
def add_customer():
    current_user = User.query.get(get_jwt_identity())
    if current_user.role != 'admin':
        return jsonify({'message': 'Admin access required.'}), 403
    
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    new_customer = User(
        role='customer',
        username=data['username'],
        city=data.get('city'),
        age=data.get('age'),
        email=data['email'],
        password=hashed_password,
        status='active'
    )
    
    db.session.add(new_customer)
    db.session.commit()
    app.logger.info(f'Customer {new_customer.username} added successfully.')
    
    return jsonify({'message': 'Customer added successfully'}), 201

# Add a new book
@app.route('/addBook', methods=['POST'])
@jwt_required()
def add_book():
    print (get_jwt_identity())
    current_user = User.query.filter_by(username = get_jwt_identity()).one()
    if current_user.role != 'admin':
        return jsonify({'message': 'Admin access required.'}), 403
    
    data = request.get_json()
    
    new_book = Book(
        name=data['name'],
        author=data['author'],
        year_published=data['year_published'],
        type=data['type'],
        max_loan_days=data['max_loan_days']
    )
    
    db.session.add(new_book)
    db.session.commit()
    app.logger.info(f'Book {new_book.name} added successfully.')
    
    return jsonify({'message': 'Book added successfully'}), 201

# Loan a book
@app.route('/loan', methods=['POST'])
@jwt_required()
def loan_book():
    data = request.get_json()
    current_user = User.query.filter_by(username = get_jwt_identity()).one()
    book = Book.query.get(data['book_id'])

    if book is None or book.status != 'available':
        return jsonify({'message': 'Book is not available for loan.'}), 400

    new_loan = Loan(
        user_id=current_user.id,
        book_id=book.id
    )
    
    book.status = 'loaned'
    
    db.session.add(new_loan)
    db.session.commit()
    app.logger.info(f'User {current_user.username} loaned book {book.name}.')
    
    return jsonify({'message': 'Book loaned successfully'}), 201

# Return a book
@app.route('/return/<int:loan_id>', methods=['POST'])
@jwt_required()
def return_book(loan_id):
    current_user = User.query.get(get_jwt_identity())
    loan = Loan.query.get(loan_id)
    
    if loan is None or loan.user_id != current_user.id:
        return jsonify({'message': 'Invalid loan or not authorized.'}), 403
    
    loan.return_date = datetime.now()
    book = Book.query.get(loan.book_id)
    book.status = 'available'
    
    db.session.commit()
    app.logger.info(f'User {current_user.username} returned book {book.name}.')
    
    return jsonify({'message': 'Book returned successfully'}), 200

# Display all books
@app.route('/books', methods=['GET'])
@jwt_required()
def display_books():
    current_user = get_jwt_identity()
    try:
        books = Book.query.filter(Book.status != 'non-available').all()
        return jsonify([{
            'index': index,
            'id': book.id,
            'name': book.name,
            'author': book.author,
            'year_published': book.year_published,
            'type': book.type.name,  # Assuming BookType is an Enum
            'status': book.status,
            'max_loan_days': book.max_loan_days,
            'loans': [{'loan_id': loan.id, 'user_id': loan.user_id} for loan in book.loans]
        } for index, book in enumerate(books)])
    except Exception as e:
        logging.error(f"Error fetching books: {str(e)}")
        return jsonify({"error": "Unable to fetch books"}), 422

# Display all customers (admin only)
@app.route('/customers', methods=['GET'])
@jwt_required()
def display_customers():
    current_user = User.query.filter_by(username = get_jwt_identity()).one()
    if current_user.role != 'admin':
        return jsonify({'message': 'Admin access required.'}), 403
    
    customers = User.query.filter_by(role='customer').all()
    return jsonify([{'id': customer.id, 'username': customer.username, 'city' : customer.city, 'age': customer.age, 'role': customer.role, 'email': customer.email, 'status': customer.status} for customer in customers])

# Display all loans
@app.route('/loans', methods=['GET'])
@jwt_required()
def display_loans():
    current_user = User.query.filter_by(username = get_jwt_identity()).one()
    
    if current_user.role == 'admin':
        loans = Loan.query.all()
    else:
        loans = Loan.query.filter_by(user_id=current_user.id).all()
    
    return jsonify([{'id': loan.id, 'book_id': loan.book_id, 'loan_date': loan.loan_date, 'return_date': loan.return_date} for loan in loans])

# Display late loans
@app.route('/loans/late', methods=['GET'])
@jwt_required()
def display_late_loans():
    current_user = User.query.get(get_jwt_identity())
    current_time = datetime.utcnow()

    if current_user.role == 'admin':
        late_loans = Loan.query.filter((Loan.return_date == None) & (Loan.loan_date < current_time)).all()
    else:
        late_loans = Loan.query.filter((Loan.return_date == None) & (Loan.loan_date < current_time), Loan.user_id == current_user.id).all()
    
    return jsonify([{'id': loan.id, 'book_id': loan.book_id, 'loan_date': loan.loan_date} for loan in late_loans])

# Find book by name and by author
@app.route('/books/search', methods=['GET'])
@jwt_required()
def find_book():
    book_name = request.args.get('name')
    author_name = request.args.get('author')
    
    # Build the query
    query = Book.query
    if book_name:
        query = query.filter(Book.name.ilike(f'%{book_name}%'))
    if author_name:
        query = query.filter(Book.author.ilike(f'%{author_name}%'))
    books = query.all()
    
    return jsonify([{'id': book.id, 'name': book.name, 'author': book.author, 'year_published': book.year_published, 'status': book.status} for book in books])


# Find customer by name (admin only)
@app.route('/customers/search', methods=['GET'])
@jwt_required()
def find_customer():
    current_user = User.query.get(get_jwt_identity())
    if current_user.role != 'admin':
        return jsonify({'message': 'Admin access required.'}), 403
    
    customer_name = request.args.get('name')
    customers = User.query.filter(User.username.ilike(f'%{customer_name}%')).all()
    return jsonify([{'id': c.id, 'username': c.username, 'email': c.email} for c in customers])

# Remove book (change status to non-available)
@app.route('/books/<int:book_id>', methods=['DELETE'])
@jwt_required()
def remove_book(book_id):
    current_user = User.query.filter_by(username = get_jwt_identity()).one()
    if current_user.role != 'admin':
        return jsonify({'message': 'Admin access required.'}), 403
    
    book = Book.query.get(book_id)
    if book:
        book.status = 'non-available'
        db.session.commit()
        app.logger.info(f'Book {book.name} has been removed.')
        return jsonify({'message': 'Book has been removed.'}), 200
    return jsonify({'message': 'Book not found.'}), 404

#Update book
@app.route('/books/<int:book_id>', methods=['PUT'])
@jwt_required()
def update_book(book_id):
    current_user = User.query.filter_by(username=get_jwt_identity()).one()
    if current_user.role != 'admin':
        return jsonify({'message': 'Admin access required.'}), 403

    book = Book.query.get(book_id)
    if book:
        data = request.get_json()
        
        # Update the book attributes if provided in the request data
        book.name = data.get('name', book.name)
        book.author = data.get('author', book.author)
        book.year_of_publication = data.get('year_of_publication', book.year_of_publication)
        book.type = data.get('type', book.type)
        
        db.session.commit()
        app.logger.info(f'Book {book.name} has been updated.')
        return jsonify({'message': 'Book has been updated successfully.'}), 200

    return jsonify({'message': 'Book not found.'}), 404

# Remove customer (change status to non-available)
@app.route('/customers/<int:customer_id>', methods=['DELETE'])
@jwt_required()
def remove_customer(customer_id):
    current_user = User.query.filter_by(username = get_jwt_identity()).one()
    if current_user.role != 'admin':
        return jsonify({'message': 'Admin access required.'}), 403
    
    customer = User.query.get(customer_id)
    if customer:
        customer.status = 'non-available'
        db.session.commit()
        app.logger.info(f'Customer {customer.username} has been removed.')
        return jsonify({'message': 'Customer has been removed.'}), 200
    return jsonify({'message': 'Customer not found.'}), 404

# main Function #
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)