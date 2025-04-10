#!/usr/bin/env python3
import os
import uuid
import time
import json
import shutil
import re
from datetime import datetime
from flask import Flask, request, render_template, send_from_directory, redirect, url_for, jsonify, flash, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['STATUS_FOLDER'] = 'status'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB max file size
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'  # For session/login security
app.config['USERS_FILE'] = 'data/users.json'  # File to store user data
app.config['DIARY_FILE'] = 'data/diary_entries.json'  # File to store diary entries
app.config['SUPERADMIN_ID'] = 'admin'  # The ID of the superadmin user who can delete entries

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please login to access this page"

# Create required directories if they don't exist
for folder in [app.config['UPLOAD_FOLDER'], app.config['STATUS_FOLDER']]:
    os.makedirs(folder, exist_ok=True)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password_hash, is_admin=False, profile_pic=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_admin = is_admin
        self.profile_pic = profile_pic
        # Special flag to identify the main admin who can delete entries
        self.is_superadmin = (id == app.config['SUPERADMIN_ID'])

    @staticmethod
    def check_password(password_hash, password):
        return check_password_hash(password_hash, password)

    def get_id(self):
        return self.id

# Load users from JSON file
def load_users():
    if not os.path.exists(app.config['USERS_FILE']):
        # Create default admin if no users file exists
        users = {
            'admin': {
                'id': 'admin',
                'username': 'admin',
                'password_hash': generate_password_hash('admin'),
                'is_admin': True,
                'profile_pic': None
            }
        }
        with open(app.config['USERS_FILE'], 'w') as f:
            json.dump(users, f)
        print("Created default admin user (username: admin, password: admin)")
    
    with open(app.config['USERS_FILE'], 'r') as f:
        return json.load(f)

# Save users to JSON file
def save_users(users):
    with open(app.config['USERS_FILE'], 'w') as f:
        json.dump(users, f)

# Load diary entries from JSON file
def load_diary_entries():
    if not os.path.exists(app.config['DIARY_FILE']):
        with open(app.config['DIARY_FILE'], 'w') as f:
            json.dump([], f)
        return []
    
    with open(app.config['DIARY_FILE'], 'r') as f:
        return json.load(f)

# Save diary entries to JSON file
def save_diary_entries(entries):
    with open(app.config['DIARY_FILE'], 'w') as f:
        json.dump(entries, f)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    users = load_users()
    if user_id in users:
        user_data = users[user_id]
        return User(
            id=user_id,
            username=user_data['username'],
            password_hash=user_data['password_hash'],
            is_admin=user_data.get('is_admin', False),
            profile_pic=user_data.get('profile_pic')
        )
    return None

@app.route('/')
def index():
    # Redirect to login if not logged in
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Load all diary entries
    entries = load_diary_entries()
    entries.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Get all users for displaying profile info
    users = load_users()
    
    return render_template('index.html', entries=entries, users=users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        users = load_users()
        user_found = None
        
        # Find user by username
        for user_id, user_data in users.items():
            if user_data['username'] == username:
                user_found = User(
                    id=user_id,
                    username=user_data['username'],
                    password_hash=user_data['password_hash'],
                    is_admin=user_data.get('is_admin', False),
                    profile_pic=user_data.get('profile_pic')
                )
                break
        
        if user_found and User.check_password(user_found.password_hash, password):
            login_user(user_found)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not username or not password:
            flash('Please fill in all fields', 'danger')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
            
        # Check if username already exists
        users = load_users()
        for user_data in users.values():
            if user_data['username'] == username:
                flash('Username already exists', 'danger')
                return render_template('register.html')
        
        # Create new user
        user_id = str(uuid.uuid4())
        users[user_id] = {
            'id': user_id,
            'username': username,
            'password_hash': generate_password_hash(password),
            'is_admin': False,
            'profile_pic': None
        }
        
        save_users(users)
        flash('Registration successful! You can now login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash('You do not have permission to access the admin panel', 'danger')
        return redirect(url_for('index'))
    
    users = load_users()
    return render_template('admin.html', users=users)

@app.route('/admin/user/delete/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to delete users', 'danger')
        return redirect(url_for('index'))
    
    # Cannot delete yourself
    if user_id == current_user.id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin'))
    
    users = load_users()
    
    if user_id in users:
        del users[user_id]
        save_users(users)
        flash('User deleted successfully', 'success')
    else:
        flash('User not found', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/admin/user/toggle-admin/<user_id>', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin or not current_user.is_superadmin:
        flash('You do not have permission to change admin status', 'danger')
        return redirect(url_for('index'))
    
    # Cannot change your own admin status
    if user_id == current_user.id:
        flash('You cannot change your own admin status', 'danger')
        return redirect(url_for('admin'))
    
    users = load_users()
    
    if user_id in users:
        users[user_id]['is_admin'] = not users[user_id].get('is_admin', False)
        save_users(users)
        new_status = 'admin' if users[user_id]['is_admin'] else 'regular user'
        flash(f'User status changed to {new_status}', 'success')
    else:
        flash('User not found', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/user/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        users = load_users()
        
        # Update password if provided
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if current_password and new_password:
            if not User.check_password(users[current_user.id]['password_hash'], current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('profile'))
                
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('profile'))
                
            users[current_user.id]['password_hash'] = generate_password_hash(new_password)
            flash('Password updated successfully', 'success')
        
        # Handle profile picture upload
        if 'profile_pic' in request.files:
            profile_pic = request.files['profile_pic']
            if profile_pic.filename:
                filename = secure_filename(profile_pic.filename)
                pic_id = str(uuid.uuid4())
                pic_filename = f"{pic_id}_{filename}"
                profile_pic.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_filename))
                users[current_user.id]['profile_pic'] = pic_filename
                flash('Profile picture updated', 'success')
        
        save_users(users)
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

# Extract hashtags from content
def extract_hashtags(content):
    # Pattern to match hashtags
    hashtag_pattern = r'#(\w+)'
    return re.findall(hashtag_pattern, content)

@app.route('/create_entry', methods=['POST'])
@login_required
def create_entry():
    content = request.form.get('content', '').strip()
    if not content:
        flash('Entry content cannot be empty', 'danger')
        return redirect(url_for('index'))
        
    # Create new diary entry
    entry_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
    # Handle image upload
    image_filename = None
    if 'entry_image' in request.files:
        entry_image = request.files['entry_image']
        if entry_image.filename:
            filename = secure_filename(entry_image.filename)
            image_id = str(uuid.uuid4())
            image_filename = f"{image_id}_{filename}"
            entry_image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
    
    # Extract hashtags
    hashtags = extract_hashtags(content)
    
    new_entry = {
        'id': entry_id,
        'user_id': current_user.id,
        'content': content,
        'timestamp': timestamp,
        'image': image_filename,
        'likes': [],
        'comments': [],
        'hashtags': hashtags
    }
    
    entries = load_diary_entries()
    entries.append(new_entry)
    save_diary_entries(entries)
    
    flash('Entry created successfully', 'success')
    return redirect(url_for('index'))

@app.route('/like_entry/<entry_id>', methods=['POST'])
@login_required
def like_entry(entry_id):
    entries = load_diary_entries()
    
    for entry in entries:
        if entry['id'] == entry_id:
            if current_user.id in entry['likes']:
                entry['likes'].remove(current_user.id)
            else:
                entry['likes'].append(current_user.id)
            save_diary_entries(entries)
            break
    
    return redirect(url_for('index'))

@app.route('/add_comment/<entry_id>', methods=['POST'])
@login_required
def add_comment(entry_id):
    comment = request.form.get('comment', '').strip()
    if not comment:
        flash('Comment cannot be empty', 'danger')
        return redirect(url_for('index'))
    
    entries = load_diary_entries()
    
    for entry in entries:
        if entry['id'] == entry_id:
            comment_id = str(uuid.uuid4())
            timestamp = datetime.now().isoformat()
            
            entry['comments'].append({
                'id': comment_id,
                'user_id': current_user.id,
                'content': comment,
                'timestamp': timestamp
            })
            
            save_diary_entries(entries)
            flash('Comment added', 'success')
            break
    
    return redirect(url_for('index'))

@app.route('/delete_entry/<entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    entries = load_diary_entries()
    
    for i, entry in enumerate(entries):
        if entry['id'] == entry_id:
            # Check if user is the owner or an admin
            if entry['user_id'] == current_user.id or current_user.is_admin:
                # Delete associated image if it exists
                if entry.get('image'):
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], entry['image'])
                    if os.path.exists(image_path):
                        os.remove(image_path)
                
                # Remove the entry
                entries.pop(i)
                save_diary_entries(entries)
                flash('Entry deleted', 'success')
            else:
                flash('You do not have permission to delete this entry', 'danger')
            break
    
    return redirect(url_for('index'))

@app.route('/user/<user_id>')
@login_required
def user_profile(user_id):
    users = load_users()
    if user_id not in users:
        flash('User not found', 'danger')
        return redirect(url_for('index'))
    
    entries = load_diary_entries()
    user_entries = [entry for entry in entries if entry['user_id'] == user_id]
    user_entries.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('user_profile.html', 
                          user_data=users[user_id], 
                          entries=user_entries, 
                          users=users)

@app.route('/media/<filename>')
@login_required
def media_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/edit_entry/<entry_id>', methods=['GET', 'POST'])
@login_required
def edit_entry(entry_id):
    entries = load_diary_entries()
    
    # Find the entry
    target_entry = None
    for entry in entries:
        if entry['id'] == entry_id:
            target_entry = entry
            break
    
    if not target_entry:
        flash('Entry not found', 'danger')
        return redirect(url_for('index'))
    
    # Check if user is authorized to edit this entry
    if target_entry['user_id'] != current_user.id and not current_user.is_admin:
        flash('You do not have permission to edit this entry', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        if not content:
            flash('Entry content cannot be empty', 'danger')
            return redirect(url_for('edit_entry', entry_id=entry_id))
        
        # Update entry content and extract new hashtags
        target_entry['content'] = content
        target_entry['hashtags'] = extract_hashtags(content)
        
        # Handle image update
        if 'entry_image' in request.files:
            entry_image = request.files['entry_image']
            if entry_image.filename:
                # Remove old image if it exists
                if target_entry.get('image'):
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], target_entry['image'])
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                # Save new image
                filename = secure_filename(entry_image.filename)
                image_id = str(uuid.uuid4())
                image_filename = f"{image_id}_{filename}"
                entry_image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
                target_entry['image'] = image_filename
        
        # Save the updated entries
        save_diary_entries(entries)
        flash('Entry updated successfully', 'success')
        
        # Redirect back to the appropriate page
        if request.form.get('redirect_to') == 'profile':
            return redirect(url_for('user_profile', user_id=current_user.id))
        else:
            return redirect(url_for('index'))
    
    # For GET request, render the edit form
    users = load_users()
    return render_template('edit_entry.html', entry=target_entry, users=users)

@app.route('/hashtag/<tag>')
@login_required
def view_hashtag(tag):
    entries = load_diary_entries()
    
    # Filter entries containing the hashtag
    tagged_entries = []
    for entry in entries:
        hashtags = entry.get('hashtags', [])
        # If entry doesn't have hashtags field, extract them from content
        if not hashtags and 'content' in entry:
            hashtags = extract_hashtags(entry['content'])
            entry['hashtags'] = hashtags
        
        if tag in hashtags:
            tagged_entries.append(entry)
    
    # Sort by timestamp, newest first
    tagged_entries.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Get users for displaying profile info
    users = load_users()
    
    return render_template('hashtag.html', entries=tagged_entries, users=users, hashtag=tag)

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '').strip().lower()
    
    if not query:
        return redirect(url_for('index'))
    
    # Load entries and users
    entries = []
    users = {}
    
    if os.path.exists('data/entries.json'):
        with open('data/entries.json', 'r') as f:
            entries = json.load(f)
    
    if os.path.exists('data/users.json'):
        with open('data/users.json', 'r') as f:
            users = json.load(f)
    
    # Filter entries by search query
    search_results = []
    
    for entry in entries:
        # Search in content
        if query in entry['content'].lower():
            search_results.append(entry)
            continue
            
        # Search in hashtags
        if 'hashtags' in entry:
            for tag in entry['hashtags']:
                if query in tag.lower() or query == '#' + tag.lower():
                    search_results.append(entry)
                    break
    
    # Sort by timestamp in descending order
    search_results.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('search_results.html', entries=search_results, users=users, query=query)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 