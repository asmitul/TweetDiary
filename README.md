# TweetDiary - Your Personal Twitter-like Diary

TweetDiary is a web application that provides a private Twitter-like experience for personal journaling. Create posts, add images, like entries, comment, and use hashtags - all in a familiar social media interface but for your personal use.

## Features

- **User Management**
  - Secure user registration and login
  - Customizable user profiles with profile pictures
  - Password management
  - Admin dashboard for user administration

- **Diary Entries**
  - Create short-form diary entries (tweets) with a 280 character limit
  - Attach images to your entries
  - Like your favorite memories
  - Comment on entries
  - Use hashtags to categorize and search your entries
  - Edit or delete entries

- **Social Features**
  - View entries from other users (if sharing is enabled)
  - User profiles to view specific user's entries
  - Like and comment on entries
  - Explore entries by hashtag

- **Interface**
  - Clean, modern Twitter-inspired UI
  - Responsive design works on desktop and mobile
  - Real-time character counter
  - Interactive comments section

## Prerequisites

- Python 3.6+
- Flask
- Modern web browser

## Installation

1. Clone this repository:
   ```
   git clone <repository-url>
   cd TweetDiary
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python app.py
   ```

4. Open your browser and navigate to:
   ```
   http://localhost:8091
   ```

## Docker Deployment

For easier deployment, use Docker:

1. Build the Docker image:
   ```
   docker build -t tweetdiary .
   ```

2. Run the container:
   ```
   docker run -d \
     --name tweetdiary \
     -p 8091:8091 \
     -v "$(pwd)/uploads:/app/uploads" \
     -v "$(pwd)/data:/app/data" \
     --restart unless-stopped \
     tweetdiary
   ```

## Automated Deployment

This application supports automated deployment using GitHub Actions with a self-hosted runner. The deployment workflow is defined in `.github/workflows/deploy.yml`.

## File Structure

- `/uploads`: Storage for user uploads (profile pictures and entry images)
- `/status`: Status files for processing
- `/templates`: HTML templates for the web interface
- `/static`: CSS, JavaScript, and other static assets
- `app.py`: Main application file
- `users.json`: User data storage
- `diary_entries.json`: Diary entries storage

## Security Considerations

- User passwords are securely hashed
- File upload validation to prevent malicious file uploads
- Access control to prevent unauthorized access to entries
- Admin functionality restricted to authorized users

## First-time Setup

When first running the application, a default admin user is created:
- Username: admin
- Password: admin

**Important**: Change this password immediately after first login by going to the profile settings page.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request 