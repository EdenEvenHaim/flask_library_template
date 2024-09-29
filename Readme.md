# Library Management System API

This is a RESTful API built using Flask for managing a library system. It allows users to register, log in, manage books, and handle loans. The API supports authentication via JWT and uses SQLite for data storage.

## Features

- User registration and login
- Admin and customer roles
- CRUD operations for books and customers
- Loan management for books
- Search functionality for books and customers
- Late loan tracking
- CORS enabled for cross-origin requests
- Logger setup for monitoring actions

## Technologies Used

- Python
- Flask
- Flask-SQLAlchemy
- Flask-Bcrypt
- Flask-JWT-Extended
- Flask-CORS
- SQLite

## Installation

1. Clone the repository:

   ```bash
   git clone <https://github.com/EdenEvenHaim/flask_library_template.git>
   cd <repository-directory>

2. Create a virtual environment:
    py -m virtualenv env

3. Install the required packages:
    pip install -r requirements.txt

The API will be available at http://127.0.0.1:5000.
## Endpoints:
    * Registration: POST /register
        Requires JSON body with username, password, and email.
    * Login: POST /login
        Requires JSON body with username and password.
    * Add Customer: POST /customers
        Requires JWT token. Admin access required.
    * Add Book: POST /books
        Requires JWT token. Admin access required.
    * Loan a Book: POST /loan
        Requires JWT token. Body should contain book_id.
    * Return a Book: POST /return/<loan_id>
        Requires JWT token.
    * Display All Books: GET /books
        Requires JWT token.
    * Display All Customers: GET /customers
        Requires JWT token. Admin access required.
    * Display All Loans: GET /loans
        Requires JWT token.
    * Find Book: GET /books/search
        Query parameters: name, author.
    * Find Customer: GET /customers/search
        Requires JWT token. Admin access required. Query parameter: name.
    * Remove Book: DELETE /books/<book_id>
        Requires JWT token. Admin access required.
    * Remove Customer: DELETE /customers/<customer_id>
        Requires JWT token. Admin access required.

## Logging
The application includes logging for registration attempts, login attempts, and actions performed by users. Check the console output for log messages.