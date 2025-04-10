# PDF to Image Web Application

A web-based application that allows users to:
- Upload PDF files
- Convert PDFs to high-quality images
- View the converted images in a web browser
- Download individual images or all images as a ZIP archive

## Features

- Simple and intuitive web interface
- PDF processing options:
  - Adjustable DPI (resolution)
  - Page rotation options
  - Split double pages
  - Crop margins to remove artifacts
- Responsive design for mobile and desktop
- Background processing with real-time status updates
- Progress tracking for large PDF files
- Dark/light mode for image viewing
- Disk usage monitoring and file cleanup
- Docker-based for easy deployment
- CPU usage allocation (50% of all cores)
- Production-ready with Gunicorn WSGI server
- GitHub Actions deployment support

## Prerequisites

- Docker

No other dependencies needed to be installed locally as everything runs in the Docker container.

## Quick Start - Local Deployment

1. Clone this repository:
   ```
   git clone <repository-url>
   cd pdf2img
   ```

2. Make the local runner script executable:
   ```
   chmod +x local-run.sh
   ```

3. Start the application:
   ```
   ./local-run.sh start
   ```

4. Open your browser and navigate to:
   ```
   http://localhost:8090
   ```

## Local Usage Options

The `local-run.sh` script provides several commands:

```
./local-run.sh [command]
```

Commands:
- `start`: Start the application
- `stop`: Stop the application
- `restart`: Rebuild and restart the application
- `status`: Check if the application is running

Examples:
```
# Start the application
./local-run.sh start

# Check status
./local-run.sh status

# Rebuild and restart
./local-run.sh restart

# Stop the application
./local-run.sh stop
```

## How It Works

1. Upload a PDF file through the web interface
2. Select processing options:
   - DPI (resolution quality)
   - Rotation (auto-detect or specific angle)
   - Split pages option (for books with two pages per sheet)
   - Crop margins (to remove unwanted borders)
3. Click "Upload and Convert" to process the file
4. Monitor processing progress with real-time status updates
5. View the results in the web browser when processing is complete
6. Download individual images or all images as a ZIP file
7. Use the cleanup feature to free up disk space when necessary

## Technical Details

This application uses:
- Flask for the web framework
- Gunicorn as the production WSGI server with gevent worker for better concurrency
- Background processing for handling large files asynchronously
- Real-time status tracking with AJAX polling
- pdf2image for PDF processing
- OpenCV for image processing and deskewing
- Bootstrap for the user interface
- Docker for containerization

## Directory Structure

- `/uploads`: Temporary storage for uploaded PDF files
- `/output`: Storage for processed images
- `/status`: Status files for tracking background processing
- `/templates`: HTML templates
- `/static`: CSS and static assets

## Automated Deployment

This application supports automated deployment using GitHub Actions with a self-hosted runner:

1. Set up a self-hosted runner on your server
2. Push changes to the main branch of your repository
3. GitHub Actions will automatically deploy the application to your server

The deployment workflow performs the following steps:
- Checks out the latest code
- Stops and removes any existing container
- Builds a new Docker image
- Creates necessary directories for uploads and output
- Starts a new container with CPU limitations
- Verifies that the application is running correctly

### GitHub Actions Configuration

The deployment workflow is defined in `.github/workflows/deploy.yml` and uses direct Docker commands to:

- Build the Docker image
- Start the container with proper volume mounts
- Limit CPU usage to 50%
- Expose the application on port 8090

To manually trigger a deployment, go to the Actions tab in your GitHub repository and run the "Deploy to Server" workflow.

## Manual Docker Setup

If you prefer to run commands manually:

1. Build the Docker image:
   ```
   docker build -t pdf-to-image-web .
   ```

2. Create necessary directories:
   ```
   mkdir -p uploads output status
   chmod -R 777 uploads output status
   ```

3. Run the container:
   ```
   docker run -d \
     --name pdf2img-app \
     --cpus=3.0 \
     -p 8090:8090 \
     -v "$(pwd)/uploads:/app/uploads" \
     -v "$(pwd)/output:/app/output" \
     -v "$(pwd)/status:/app/status" \
     --restart unless-stopped \
     pdf-to-image-web
   ```

## Resource Limitations

The Docker container is configured to use a configurable amount of CPU cores. By default, this is set to 3.0 cores (50% of a 6-core server). You can adjust this allocation by:

1. For GitHub Actions deployment: Change the `CPU_CORES` environment variable in `.github/workflows/deploy.yml`
2. For local deployment: Modify the `CPU_CORES` variable at the top of the `local-run.sh` script

This configuration allows for efficient PDF processing while giving you control over resource allocation based on your server's capacity.

## Production Deployment

The application uses Gunicorn as a production-grade WSGI server instead of Flask's built-in development server. This provides:

- Better performance and stability
- Multiple worker processes (4 by default)
- Proper handling of concurrent requests
- Longer timeout (120 seconds) for processing large PDF files

## License

See the [LICENSE](LICENSE) file for details.

## Maintenance

### Disk Space Management

The application includes a disk usage monitoring and cleanup feature that allows you to:

1. View current disk usage statistics for uploads, processed images, and status files
2. Free up disk space by removing completed processing jobs and their associated files
3. Automatically track disk usage with a visual breakdown of space allocation

This feature helps maintain the server's performance by preventing disk space issues, especially in high-traffic environments where many PDFs are processed. 