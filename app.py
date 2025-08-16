# Import necessary modules from Flask and its extensions
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

# --- App and Database Configuration ---

# Initialize the Flask application
app = Flask(__name__)

# Configure the secret key for session management and security
app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed'

# Configure the folder to store uploaded images
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure the SQLAlchemy database URI.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the SQLAlchemy database extension
db = SQLAlchemy(app)

# Initialize Flask-Login for handling user sessions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# --- Database Models ---

# User model for the database, inheriting from UserMixin for Flask-Login integration
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    
    # Relationship to the Event model
    events = db.relationship('Event', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Event model for the database
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    date = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    # This will now store the path to the uploaded image
    image_url = db.Column(db.String(400), nullable=True)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# --- User Loader for Flask-Login ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Routes ---

# Route to serve uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Home page: Displays all events
@app.route('/')
def index():
    events = Event.query.all()
    return render_template('index.html', events=events)

# Registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(username=username)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
        
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

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
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
        image_file = request.files.get('image')
        
        image_url = None
        # Check if an image file was uploaded
        if image_file and image_file.filename != '':
            # Secure the filename to prevent malicious file names
            filename = secure_filename(image_file.filename)
            # Save the file to the upload folder
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # Create the URL for the saved image
            image_url = url_for('uploaded_file', filename=filename)

        new_event = Event(
            title=title,
            date=date,
            description=description,
            location=location,
            image_url=image_url,
            user_id=current_user.id
        )
        
        db.session.add(new_event)
        db.session.commit()
        
        flash('Event posted successfully!', 'success')
        return redirect(url_for('index'))
        
    return render_template('post_event.html')

# Route to delete an event
@app.route('/delete_event/<int:event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    # Corrected the function call from get_or_44 to get_or_404
    event_to_delete = Event.query.get_or_404(event_id)
    
    if event_to_delete.author != current_user:
        flash('You do not have permission to delete this event.', 'danger')
        return redirect(url_for('index'))
    
    db.session.delete(event_to_delete)
    db.session.commit()
    
    flash('Event deleted successfully.', 'success')
    return redirect(url_for('dashboard'))

# --- Main Execution ---

if __name__ == '__main__':
    # Create the 'instance' and 'uploads' directories if they don't exist
    instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
    uploads_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), app.config['UPLOAD_FOLDER'])
    if not os.path.exists(instance_path):
        os.makedirs(instance_path)
    if not os.path.exists(uploads_path):
        os.makedirs(uploads_path)

    with app.app_context():
        db.create_all()
    
    app.run(debug=True)
