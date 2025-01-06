import logging
from flask import Flask, request, jsonify, render_template, redirect, abort
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import current_user
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone

# initialize the limiter
limiter = Limiter(key_func=get_remote_address, default_limits=["5 per minute"])

app = Flask(__name__)
CORS(app)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = (
    # WARNING MAKE FILL THE INfORMATION BELOW
    "mssql+pyodbc://Joseph:Pa$$w0rd@WIN-991Q0G7VUUT\\SQLEXPRESS/Testing"
    "?driver=ODBC+Driver+17+for+SQL+Server"
)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class AppUser(db.Model):
   id = db.Column(db.Integer, primary_key=True)
   username = db.Column(db.String(80), nullable=False)
   password = db.Column(db.String(120), nullable=False)
   role = db.Column(db.String(50), default='user')

class Transaction(db.Model):
   id = db.Column(db.Integer, primary_key=True)
   user_id = db.Column(db.Integer, db.ForeignKey('app_user.id'), nullable=False)
   amount = db.Column(db.Float, nullable=False)
   date = db.Column(db.DateTime, default=db.func.now())

# Rate-limiting to prevent DoS
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    user = AppUser.query.filter(AppUser.username == username).first()

    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        response_data = {
            'message': 'Login successful',
            'role': user.role
        }
        return jsonify(response_data), 200

    return jsonify({'message': 'Invalid credentials'}), 401

def before_request():
    if not request.is_secure:
        url = request.url.replace('http://', 'https://')
        return redirect(url, 301) 
 
@app.route('/')
def home():
    return render_template('index.html')

# Set up logging
logging.basicConfig(filename='app.log', level=logging.INFO)

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = AppUser(username=data['username'], password=hashed_password, role='user')
    db.session.add(new_user)
    db.session.commit()
    logging.info(f"User {data['username']} registered at {datetime.utcnow()}")
    return jsonify({"message": "User registered successfully!"})

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

# Initialize JWT
app.config['JWT_SECRET_KEY'] = 'hard_to_find_out'
jwt= JWTManager(app)

# logging for sensitive actions
@app.route('/some_action', methods=['POST'])
@jwt_required()
def some_action():
    user_id = get_jwt_identity()
    # Perform the action (like a transaction)
    logging.info(f"User {user_id} performed an action at {datetime.utcnow()}")
    return jsonify({'message': 'Action logged successfully'}), 200

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = AppUser.query.all()
    result = [{'id': user.id, 'username': user.username} for user in users]  # Expose only necessary data
    return jsonify(result), 200

# Check permissions
def roles_required(*roles):
    def wrapper(func):
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                abort(403)
            return func(*args, **kwargs)
        return wrapped
    return wrapper

# Role-based access control example
@app.route('/admin', methods=['GET'])
@roles_required('admin')  # Ensure only admin users can access
def admin_dashboard():
    return jsonify({'message': 'Welcome Admin'})

@app.route('/transactions', methods=['POST'])
@jwt_required()
def add_transaction():
    try:
        user_id = get_jwt_identity()  # Get user ID from JWT token
        data = request.json  # Retrieve data from request
        amount = data.get('amount')  # Get 'amount' field

        if amount is None or amount <= 0:
            return jsonify({'message': 'Invalid transaction amount'}), 400

        # Add transaction to database
        transaction = Transaction(user_id=user_id, amount=amount)
        db.session.add(transaction)
        db.session.commit()

        return jsonify({'message': 'Transaction added successfully'}), 201
    except Exception as e:
        logging.error(f"Error adding transaction: {e}")
        return jsonify({'message': 'Failed to add transaction'}), 500


@app.route('/add_transaction', methods=['GET', 'POST'])
@jwt_required()  # Ensures only logged-in users can access
def add_transaction_page():
    if request.method == 'POST':
        amount = request.form.get('amount')
        user_id = get_jwt_identity()  # Get the logged-in user's ID
        if not amount:
            return render_template('add_transaction.html', message="Amount is required.")
        try:
            transaction = Transaction(user_id=user_id, amount=float(amount))
            db.session.add(transaction)
            db.session.commit()
            return render_template('add_transaction.html', message="Transaction added successfully!")
        except Exception as e:
            return render_template('add_transaction.html', message=f"Error: {str(e)}")
    return render_template('add_transaction.html', message=None)


@app.route('/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    transactions = Transaction.query.all()
    result = [
        {
            'id': t.id,
            'user_id': t.user_id,
            'amount': t.amount,
            'date': t.date
        }
        for t in transactions
    ]
    return jsonify(result), 200

if __name__ == '__main__':
    with app.app_context():
       if not AppUser.query.first():  # Check if there are no users
        from werkzeug.security import generate_password_hash
        admin_user = AppUser(
            username="admin",
            password=generate_password_hash("adminpassword", method="pbkdf2:sha256"),
            role="admin"
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin user created. Username: admin, Password: adminpassword")
        db.create_all()
    app.run(debug=True)

@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"message": "Page not found"}), 404

@app.errorhandler(403)
def forbidden_access(e):
    return jsonify({"message": "Access forbidden"}), 403

@app.errorhandler(500)
def internal_error(e):
    logging.error(f"Internal server error: {e}")
    return jsonify({"message": "An internal server error occurred"}), 500
