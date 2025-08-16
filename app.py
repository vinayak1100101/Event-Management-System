# Import necessary modules from Flask and its extensions
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

# --- App and Database Configuration ---

# Initialize the Flask application
app = Flask(__name__)

# Configure the secret key for session management and security
# It's important to keep this key secret in a production environment
app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed'

# Configure the SQLAlchemy database URI.
# We use os.path.join to create a platform-independent path.
# 'instance' is a conventional folder for database files that shouldn't be in version control.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the SQLAlchemy database extension
db = SQLAlchemy(app)

# Initialize Flask-Login for handling user sessions
login_manager = LoginManager()
login_manager.init_app(app)
# Set the view to redirect to when a user needs to log in
login_manager.login_view = 'login'


# --- Database Models ---

# User model for the database, inheriting from UserMixin for Flask-Login integration
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    
    # Relationship to the Event model
    # 'author' back-references the User model from the Event model
    events = db.relationship('Event', backref='author', lazy=True)

    # Method to set the password by hashing it
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Method to check if the provided password matches the hashed password
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Event model for the database
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    date = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    
    # Foreign key to link an event to a user
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# --- User Loader for Flask-Login ---

# This function is used by Flask-Login to reload the user object from the user ID stored in the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Routes ---

# Home page: Displays all events
@app.route('/')
def index():
    # Query all events from the database
    events = Event.query.all()
    return render_template('index.html', events=events)

# Registration page: Handles new user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    # If the user is already logged in, redirect to the home page
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if the username already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        
        # Create a new user and set their password
        new_user = User(username=username)
        new_user.set_password(password)
        
        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

# Login page: Handles user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If the user is already logged in, redirect to the home page
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Find the user by username
        user = User.query.filter_by(username=username).first()
        
        # If user doesn't exist or password doesn't match, show an error
        if not user or not user.check_password(password):
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
        
        # Log the user in
        login_user(user)
        flash('Logged in successfully!', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Dashboard: Shows events posted by the current user
@app.route('/dashboard')
@login_required
def dashboard():
    # Query events created by the currently logged-in user
    user_events = Event.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', events=user_events)

# Post a new event page
@app.route('/post_event', methods=['GET', 'POST'])
@login_required
def post_event():
    if request.method == 'POST':
        title = request.form.get('title')
        date = request.form.get('date')
        description = request.form.get('description')
        location = request.form.get('location')
        
        # Create a new event associated with the current user
        new_event = Event(
            title=title,
            date=date,
            description=description,
            location=location,
            user_id=current_user.id
        )
        
        # Add the new event to the database
        db.session.add(new_event)
        db.session.commit()
        
        flash('Event posted successfully!', 'success')
        return redirect(url_for('index'))
        
    return render_template('post_event.html')

# Route to delete an event
@app.route('/delete_event/<int:event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    # Find the event by its ID
    event_to_delete = Event.query.get_or_404(event_id)
    
    # Ensure the current user is the author of the event
    if event_to_delete.author != current_user:
        flash('You do not have permission to delete this event.', 'danger')
        return redirect(url_for('index'))
    
    # Delete the event from the database
    db.session.delete(event_to_delete)
    db.session.commit()
    
    flash('Event deleted successfully.', 'success')
    return redirect(url_for('dashboard'))

# --- Main Execution ---

if __name__ == '__main__':
    # Create the 'instance' directory if it doesn't exist
    instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)

    # Create all database tables within the app context
    with app.app_context():
        db.create_all()
    
    # Run the Flask app in debug mode
    app.run(debug=True)
