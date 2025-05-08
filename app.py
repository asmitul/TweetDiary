#!/usr/bin/env python3
import os
import uuid
import time
import json
import shutil
import re
from datetime import datetime
import pytz  # Add pytz for timezone support
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
app.config['JSON_AS_ASCII'] = False  # Ensure JSON responses include non-ASCII characters
app.config['ENTRIES_PER_PAGE'] = 10  # Number of entries to display per page
app.config['TIMEZONE'] = 'Europe/Istanbul'  # Set default timezone to Istanbul
app.config['ALLOWED_IMAGE_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed image extensions
app.config['ALLOWED_EXCALIDRAW_EXTENSIONS'] = {'excalidraw'}  # Allowed Excalidraw extensions

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please login to access this page"

# Create required directories if they don't exist
for folder in [app.config['UPLOAD_FOLDER'], app.config['STATUS_FOLDER'], 'data']:
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
        with open(app.config['USERS_FILE'], 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False)
        print("Created default admin user (username: admin, password: admin)")
    
    with open(app.config['USERS_FILE'], 'r', encoding='utf-8') as f:
        return json.load(f)

# Save users to JSON file
def save_users(users):
    with open(app.config['USERS_FILE'], 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False)

# Load diary entries from JSON file
def load_diary_entries():
    if not os.path.exists(app.config['DIARY_FILE']):
        with open(app.config['DIARY_FILE'], 'w', encoding='utf-8') as f:
            json.dump([], f, ensure_ascii=False)
        return []
    
    with open(app.config['DIARY_FILE'], 'r', encoding='utf-8') as f:
        return json.load(f)

# Save diary entries to JSON file
def save_diary_entries(entries):
    with open(app.config['DIARY_FILE'], 'w', encoding='utf-8') as f:
        json.dump(entries, f, ensure_ascii=False)

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

# Function to format timestamps to Istanbul timezone
def format_timestamp(timestamp_str, format_str="%Y-%m-%d %H:%M"):
    """Convert ISO timestamp string to Istanbul timezone and format it"""
    # Parse the ISO timestamp
    dt = datetime.fromisoformat(timestamp_str)
    # If the datetime is naive (no timezone info), assume it's UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=pytz.UTC)
    # Convert to Istanbul timezone
    istanbul_tz = pytz.timezone(app.config['TIMEZONE'])
    istanbul_dt = dt.astimezone(istanbul_tz)
    # Format the datetime
    return istanbul_dt.strftime(format_str)

# Add the formatter function to Jinja environment
@app.template_filter('istanbul_time')
def istanbul_time_filter(timestamp_str, format_str="%Y-%m-%d %H:%M"):
    return format_timestamp(timestamp_str, format_str)

@app.template_filter('hashtag')
def hashtag_filter(s):
    if not s:
        return ""
    # Use a more robust regex that handles various hashtag formats and avoids partial matches within words.
    # It looks for a #, followed by one or more word characters (letters, numbers, underscore).
    # It also ensures that the character preceding the # is not a word character to avoid partial matches.
    # The (?<!\\w) is a negative lookbehind asserting that what precedes is not a word character.
    # The (\\w+) captures the hashtag itself.
    # The link will point to /hashtag/<tag_name>
    return re.sub(r"(?<!\\w)#(\\w+)", r'<a href="/hashtag/\\1">#\\1</a>', s, flags=re.UNICODE)

@app.route('/')
@app.route('/page/<int:page>')
def index(page=1):
    # Redirect to login if not logged in
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Load all diary entries
    entries = load_diary_entries()
    
    # Filter out private entries from other users
    filtered_entries = []
    for entry in entries:
        # Include the entry if:
        # 1. It belongs to the current user, OR
        # 2. It's not private, OR
        # 3. Current user is an admin
        # 4. AND it's not archived (for any user)
        if ((entry['user_id'] == current_user.id or 
            not entry.get('is_private', False) or 
            current_user.is_admin) and
            not entry.get('is_archived', False)):
            filtered_entries.append(entry)
    
    # Sort entries by timestamp (newest first)
    filtered_entries.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Implement pagination
    entries_per_page = app.config['ENTRIES_PER_PAGE']
    total_entries = len(filtered_entries)
    total_pages = (total_entries + entries_per_page - 1) // entries_per_page  # Ceiling division
    
    # Ensure page is within valid range
    if page < 1:
        page = 1
    elif page > total_pages and total_pages > 0:
        page = total_pages
    
    # Get entries for current page
    start_idx = (page - 1) * entries_per_page
    end_idx = min(start_idx + entries_per_page, total_entries)
    paginated_entries = filtered_entries[start_idx:end_idx]
    
    # Get all users for displaying profile info
    users = load_users()
    
    return render_template('index.html', 
                          entries=paginated_entries, 
                          users=users,
                          current_page=page,
                          total_pages=total_pages)

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
                if not is_image_file(profile_pic.filename):
                    flash('Invalid image file type for profile picture.', 'danger')
                    return redirect(url_for('profile'))
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
    # Pattern to match hashtags - updated to properly handle Unicode characters including Uyghur
    hashtag_pattern = r'#(\w+)'
    return re.findall(hashtag_pattern, content, re.UNICODE)

# Function to check if a file has an allowed extension
def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def is_image_file(filename):
    return allowed_file(filename, app.config['ALLOWED_IMAGE_EXTENSIONS'])

def is_excalidraw_file(filename):
    return allowed_file(filename, app.config['ALLOWED_EXCALIDRAW_EXTENSIONS'])

@app.route('/create_entry', methods=['POST'])
@login_required
def create_entry():
    content = request.form.get('content', '').strip()
    if not content:
        flash('Entry content cannot be empty', 'danger')
        return redirect(url_for('index'))
        
    # Check if the entry is private
    is_private = request.form.get('is_private') == 'on'
    
    # Create new diary entry
    entry_id = str(uuid.uuid4())
    timestamp = datetime.now(pytz.timezone(app.config['TIMEZONE'])).isoformat()
    
    # Handle multiple image and Excalidraw file uploads
    images = []
    excalidraw_files = []
    
    if 'entry_images' in request.files:
        entry_images = request.files.getlist('entry_images')
        for file in entry_images:
            if file.filename:
                filename = secure_filename(file.filename)
                file_id = str(uuid.uuid4())
                file_filename = f"{file_id}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_filename))
                
                if is_image_file(filename):
                    images.append(file_filename)
                elif is_excalidraw_file(filename):
                    excalidraw_files.append(file_filename)
    
    # Extract hashtags
    hashtags = extract_hashtags(content)
    
    new_entry = {
        'id': entry_id,
        'user_id': current_user.id,
        'content': content,
        'timestamp': timestamp,
        'images': images,
        'excalidraw_files': excalidraw_files,
        'likes': [],
        'comments': [],
        'hashtags': hashtags,
        'is_private': is_private,
        'is_archived': False
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
    
    # Check if the request is coming from the tweet page
    referrer = request.referrer
    if referrer and '/tweet/' in referrer:
        return redirect(url_for('view_tweet', entry_id=entry_id))
    
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
            timestamp = datetime.now(pytz.timezone(app.config['TIMEZONE'])).isoformat()
            
            entry['comments'].append({
                'id': comment_id,
                'user_id': current_user.id,
                'content': comment,
                'timestamp': timestamp
            })
            
            save_diary_entries(entries)
            flash('Comment added', 'success')
            break
    
    # Check if the request is coming from the tweet page
    referrer = request.referrer
    if referrer and '/tweet/' in referrer:
        return redirect(url_for('view_tweet', entry_id=entry_id))
    
    return redirect(url_for('index'))

@app.route('/edit_comment/<entry_id>/<comment_id>', methods=['GET', 'POST'])
@login_required
def edit_comment(entry_id, comment_id):
    entries = load_diary_entries()
    
    # Find the entry and comment
    target_entry = None
    target_comment = None
    
    for entry in entries:
        if entry['id'] == entry_id:
            target_entry = entry
            for comment in entry['comments']:
                if comment['id'] == comment_id:
                    target_comment = comment
                    break
            break
    
    if not target_entry or not target_comment:
        flash('Comment not found', 'danger')
        return redirect(url_for('index'))
    
    # Check if the user is the comment owner or admin
    if target_comment['user_id'] != current_user.id and not current_user.is_admin:
        flash('You do not have permission to edit this comment', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        # Update the comment
        new_content = request.form.get('comment_content', '').strip()
        if not new_content:
            flash('Comment cannot be empty', 'danger')
        else:
            target_comment['content'] = new_content
            # No need to update timestamp, we'll leave it as the original
            save_diary_entries(entries)
            flash('Comment updated successfully', 'success')
        
        # Always redirect back to the tweet page after editing a comment
        return redirect(url_for('view_tweet', entry_id=entry_id))
    
    # GET request - return the edit form
    return render_template('edit_comment.html', entry=target_entry, comment=target_comment)

@app.route('/delete_comment/<entry_id>/<comment_id>', methods=['POST'])
@login_required
def delete_comment(entry_id, comment_id):
    entries = load_diary_entries()
    
    # Find the entry and comment
    for entry in entries:
        if entry['id'] == entry_id:
            for i, comment in enumerate(entry['comments']):
                if comment['id'] == comment_id:
                    # Check if the user is the comment owner or admin
                    if comment['user_id'] != current_user.id and not current_user.is_admin:
                        flash('You do not have permission to delete this comment', 'danger')
                        return redirect(url_for('index'))
                    
                    # Remove the comment
                    entry['comments'].pop(i)
                    save_diary_entries(entries)
                    flash('Comment deleted successfully', 'success')
                    break
            break
    
    # Check if the request is coming from the tweet page
    referrer = request.referrer
    if referrer and '/tweet/' in referrer:
        return redirect(url_for('view_tweet', entry_id=entry_id))
    
    return redirect(url_for('index'))

@app.route('/delete_entry/<entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    entries = load_diary_entries()
    
    for i, entry in enumerate(entries):
        if entry['id'] == entry_id:
            # Check if user is the owner or an admin
            if entry['user_id'] == current_user.id or current_user.is_admin:
                # Delete associated image files if they exist
                if entry.get('images'):
                    for image in entry['images']:
                        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image)
                        if os.path.exists(image_path):
                            os.remove(image_path)
                
                # Delete associated Excalidraw files if they exist
                if entry.get('excalidraw_files'):
                    for excalidraw_file in entry['excalidraw_files']:
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], excalidraw_file)
                        if os.path.exists(file_path):
                            os.remove(file_path)
                
                # Remember the user ID before removing the entry
                user_id = entry['user_id']
                
                # Remove the entry
                entries.pop(i)
                save_diary_entries(entries)
                
                flash('Entry deleted successfully', 'success')
                
                # Redirect to user profile if coming from there
                referrer = request.referrer
                if referrer and f'/user/{user_id}' in referrer:
                    return redirect(url_for('user_profile', user_id=user_id))
                
                return redirect(url_for('index'))
            else:
                flash('You do not have permission to delete this entry', 'danger')
                return redirect(url_for('index'))
    
    flash('Entry not found', 'danger')
    return redirect(url_for('index'))

@app.route('/user/<user_id>')
@app.route('/user/<user_id>/page/<int:page>')
@login_required
def user_profile(user_id, page=1):
    users = load_users()
    if user_id not in users:
        flash('User not found', 'danger')
        return redirect(url_for('index'))
    
    entries = load_diary_entries()
    user_entries = []
    
    for entry in entries:
        if entry['user_id'] == user_id:
            # Show entry if:
            # 1. Current user is viewing their own profile, OR
            # 2. The entry is not private, OR
            # 3. Current user is an admin
            if (current_user.id == user_id or 
                not entry.get('is_private', False) or 
                current_user.is_admin):
                user_entries.append(entry)
                
    user_entries.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Implement pagination
    entries_per_page = app.config['ENTRIES_PER_PAGE']
    total_entries = len(user_entries)
    total_pages = (total_entries + entries_per_page - 1) // entries_per_page  # Ceiling division
    
    # Ensure page is within valid range
    if page < 1:
        page = 1
    elif page > total_pages and total_pages > 0:
        page = total_pages
    
    # Get entries for current page
    start_idx = (page - 1) * entries_per_page
    end_idx = min(start_idx + entries_per_page, total_entries)
    paginated_entries = user_entries[start_idx:end_idx]
    
    return render_template('user_profile.html', 
                          user_data=users[user_id], 
                          entries=paginated_entries, 
                          users=users,
                          current_page=page,
                          total_pages=total_pages,
                          profile_user_id=user_id)

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
        
        # Update privacy setting
        target_entry['is_private'] = request.form.get('is_private') == 'on'
        
        # Ensure archive setting is preserved
        if 'is_archived' not in target_entry:
            target_entry['is_archived'] = False
        
        # Handle file update
        if 'entry_images' in request.files:
            entry_files = request.files.getlist('entry_images')
            new_images_uploaded = any(file.filename and is_image_file(file.filename) for file in entry_files)
            new_excalidraw_uploaded = any(file.filename and is_excalidraw_file(file.filename) for file in entry_files)

            if new_images_uploaded:
                # If new image files are being uploaded, clear old image files
                if target_entry.get('images'):
                    for old_image in target_entry['images']:
                        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image)
                        if os.path.exists(old_image_path):
                            os.remove(old_image_path)
                target_entry['images'] = [] # Initialize for new images
            
            if new_excalidraw_uploaded:
                # If new excalidraw files are being uploaded, clear old excalidraw files
                if target_entry.get('excalidraw_files'):
                    for old_file in target_entry['excalidraw_files']:
                        old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], old_file)
                        if os.path.exists(old_file_path):
                            os.remove(old_file_path)
                target_entry['excalidraw_files'] = [] # Initialize for new excalidraw files
            
            # Save all new files
            # Ensure these lists exist even if no new files of a type are uploaded, to avoid KeyErrors later if they were cleared
            if 'images' not in target_entry: target_entry['images'] = []
            if 'excalidraw_files' not in target_entry: target_entry['excalidraw_files'] = []

            for file in entry_files:
                if file.filename:
                    filename = secure_filename(file.filename)
                    file_id = str(uuid.uuid4())
                    file_filename = f"{file_id}_{filename}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_filename))
                    
                    if is_image_file(filename):
                        target_entry['images'].append(file_filename)
                    elif is_excalidraw_file(filename):
                        target_entry['excalidraw_files'].append(file_filename)
        
        # Handle backward compatibility with old entries that use 'image' instead of 'images'
        if 'image' in target_entry and 'images' not in target_entry:
            if target_entry['image']:
                target_entry['images'] = [target_entry['image']]
            else:
                target_entry['images'] = []
            del target_entry['image']
        
        # Ensure excalidraw_files field exists
        if 'excalidraw_files' not in target_entry:
            target_entry['excalidraw_files'] = []
        
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
@app.route('/hashtag/<tag>/page/<int:page>')
@login_required
def view_hashtag(tag, page=1):
    entries = load_diary_entries()
    tagged_entries = []
    
    for entry in entries:
        # Check if the entry contains the specific hashtag
        if tag in entry.get('hashtags', []):
            # Include the entry if:
            # 1. It belongs to the current user, OR
            # 2. It's not private, OR
            # 3. Current user is an admin
            if (entry['user_id'] == current_user.id or 
                not entry.get('is_private', False) or 
                current_user.is_admin):
                tagged_entries.append(entry)
    
    # Sort entries by timestamp (newest first)
    tagged_entries.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Implement pagination
    entries_per_page = app.config['ENTRIES_PER_PAGE']
    total_entries = len(tagged_entries)
    total_pages = (total_entries + entries_per_page - 1) // entries_per_page  # Ceiling division
    
    # Ensure page is within valid range
    if page < 1:
        page = 1
    elif page > total_pages and total_pages > 0:
        page = total_pages
    
    # Get entries for current page
    start_idx = (page - 1) * entries_per_page
    end_idx = min(start_idx + entries_per_page, total_entries)
    paginated_entries = tagged_entries[start_idx:end_idx]
    
    # Get all users for displaying profile info
    users = load_users()
    
    return render_template('hashtag.html', 
                          tag=tag, 
                          entries=paginated_entries, 
                          users=users,
                          current_page=page,
                          total_pages=total_pages)

@app.route('/search')
@app.route('/search/page/<int:page>')
@login_required
def search(page=1):
    query = request.args.get('q', '').strip().lower()
    if not query:
        return redirect(url_for('index'))
    
    entries = load_diary_entries()
    search_results = []
    
    for entry in entries:
        # Check if the query is in the content
        if (query in entry['content'].lower() or 
            # Or if the query matches any hashtag
            any(query in hashtag.lower() for hashtag in entry.get('hashtags', []))):
            
            # Include the entry if:
            # 1. It belongs to the current user, OR
            # 2. It's not private, OR
            # 3. Current user is an admin
            if (entry['user_id'] == current_user.id or 
                not entry.get('is_private', False) or 
                current_user.is_admin):
                search_results.append(entry)
    
    # Sort results by timestamp (newest first)
    search_results.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Implement pagination
    entries_per_page = app.config['ENTRIES_PER_PAGE']
    total_entries = len(search_results)
    total_pages = (total_entries + entries_per_page - 1) // entries_per_page  # Ceiling division
    
    # Ensure page is within valid range
    if page < 1:
        page = 1
    elif page > total_pages and total_pages > 0:
        page = total_pages
    
    # Get entries for current page
    start_idx = (page - 1) * entries_per_page
    end_idx = min(start_idx + entries_per_page, total_entries)
    paginated_results = search_results[start_idx:end_idx]
    
    # Get all users for displaying profile info
    users = load_users()
    
    return render_template('search_results.html', 
                          query=query, 
                          entries=paginated_results, 
                          users=users,
                          current_page=page,
                          total_pages=total_pages)

@app.route('/tweet/<entry_id>')
@login_required
def view_tweet(entry_id):
    entries = load_diary_entries()
    
    # Find the entry
    target_entry = None
    for entry in entries:
        if entry['id'] == entry_id:
            target_entry = entry
            break
    
    if not target_entry:
        flash('Tweet not found', 'danger')
        return redirect(url_for('index'))
    
    # Check if user is authorized to view this entry
    is_authorized = (
        target_entry['user_id'] == current_user.id or 
        not target_entry.get('is_private', False) or 
        current_user.is_admin
    )
    
    if not is_authorized:
        flash('You do not have permission to view this tweet', 'danger')
        return redirect(url_for('index'))
    
    # Get all users for displaying profile info
    users = load_users()
    
    return render_template('tweet.html', 
                          entry=target_entry,
                          users=users)

@app.route('/excalidraw/<filename>')
@login_required
def excalidraw_file(filename):
    """Serve Excalidraw files with appropriate content type and CORS headers"""
    try:
        # Get the absolute file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Check if file exists
        if not os.path.exists(file_path):
            return "File not found", 404
        
        # Read file content directly to ensure correct JSON is returned
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Create a response with the file content and proper headers
        response = app.response_class(
            response=content,
            status=200,
            mimetype='application/json'
        )
        
        # Add comprehensive CORS headers to allow embedding in iframe
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Origin, Content-Type, Accept, X-Requested-With'
        response.headers['Access-Control-Max-Age'] = '3600'
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
    except Exception as e:
        app.logger.error(f"Error serving Excalidraw file: {str(e)}")
        return str(e), 500

@app.route('/archive_entry/<entry_id>', methods=['POST'])
@login_required
def archive_entry(entry_id):
    entries = load_diary_entries()
    
    for entry in entries:
        if entry['id'] == entry_id:
            # Check if user is the owner or an admin
            if entry['user_id'] == current_user.id or current_user.is_admin:
                # Archive the entry
                entry['is_archived'] = True
                save_diary_entries(entries)
                flash('Entry archived successfully', 'success')
                
                # Redirect to user profile if coming from there
                referrer = request.referrer
                if referrer and f'/user/{entry["user_id"]}' in referrer:
                    return redirect(url_for('user_profile', user_id=entry['user_id']))
                
                return redirect(url_for('index'))
            else:
                flash('You do not have permission to archive this entry', 'danger')
                return redirect(url_for('index'))
    
    flash('Entry not found', 'danger')
    return redirect(url_for('index'))

@app.route('/unarchive_entry/<entry_id>', methods=['POST'])
@login_required
def unarchive_entry(entry_id):
    entries = load_diary_entries()
    
    for entry in entries:
        if entry['id'] == entry_id:
            # Check if user is the owner or an admin
            if entry['user_id'] == current_user.id or current_user.is_admin:
                # Unarchive the entry
                entry['is_archived'] = False
                save_diary_entries(entries)
                flash('Entry unarchived successfully', 'success')
                
                # Redirect to user profile if coming from there
                referrer = request.referrer
                if referrer and f'/user/{entry["user_id"]}' in referrer:
                    return redirect(url_for('user_profile', user_id=entry['user_id']))
                elif referrer and '/archived' in referrer:
                    return redirect(url_for('archived_entries'))
                
                return redirect(url_for('index'))
            else:
                flash('You do not have permission to unarchive this entry', 'danger')
                return redirect(url_for('index'))
    
    flash('Entry not found', 'danger')
    return redirect(url_for('index'))

@app.route('/archived')
@app.route('/archived/page/<int:page>')
@login_required
def archived_entries(page=1):
    # Load all diary entries
    entries = load_diary_entries()
    
    # Filter for archived entries that belong to the current user
    archived_entries = []
    for entry in entries:
        if entry['user_id'] == current_user.id and entry.get('is_archived', False):
            archived_entries.append(entry)
    
    # Sort entries by timestamp (newest first)
    archived_entries.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Implement pagination
    entries_per_page = app.config['ENTRIES_PER_PAGE']
    total_entries = len(archived_entries)
    total_pages = (total_entries + entries_per_page - 1) // entries_per_page  # Ceiling division
    
    # Ensure page is within valid range
    if page < 1:
        page = 1
    elif page > total_pages and total_pages > 0:
        page = total_pages
    
    # Get entries for current page
    start_idx = (page - 1) * entries_per_page
    end_idx = min(start_idx + entries_per_page, total_entries)
    paginated_entries = archived_entries[start_idx:end_idx]
    
    # Get all users for displaying profile info
    users = load_users()
    
    return render_template('archived.html', 
                          entries=paginated_entries, 
                          users=users,
                          current_page=page,
                          total_pages=total_pages)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 