#!/bin/bash

# Container settings
IMAGE_NAME="pdf-to-image-web"
CONTAINER_NAME="pdf2img-app"
PORT=8090
CPU_CORES=3.0

# Function to show usage
show_usage() {
    echo "PDF to Image Web Application - Local Runner"
    echo "Usage: $0 [command]"
    echo "Commands:"
    echo "  start    Start the application"
    echo "  stop     Stop the application"
    echo "  restart  Restart the application"
    echo "  status   Show application status"
    exit 1
}

# Check command
if [ $# -lt 1 ]; then
    show_usage
fi

# Function to check if application is running
check_app_status() {
    echo "Checking application status..."
    
    # Ensure the container is running
    if ! docker ps | grep -q $CONTAINER_NAME; then
        echo "Container is not running."
        return 1
    fi
    
    # Wait up to 60 seconds for the application to start
    echo "Waiting for Gunicorn server to start (this may take up to 60 seconds)..."
    for i in {1..12}; do
        echo "Attempt $i/12 - waiting 5 seconds..."
        sleep 5
        
        # Check container logs for successful start
        if docker logs $CONTAINER_NAME 2>&1 | grep -q "Booting worker"; then
            if curl -s http://localhost:$PORT -m 3 > /dev/null; then
                echo "✅ Local server is running at http://localhost:$PORT"
                return 0
            fi
        fi
    done
    
    echo "❌ Application failed to start properly."
    echo "Container logs:"
    docker logs $CONTAINER_NAME
    return 1
}

case "$1" in
    start)
        # Check if container exists
        if docker ps -a | grep -q $CONTAINER_NAME; then
            echo "Container already exists. Use 'restart' to rebuild."
            docker start $CONTAINER_NAME
        else
            echo "Building Docker image..."
            docker build -t $IMAGE_NAME .
            
            echo "Creating directories..."
            mkdir -p uploads output status
            chmod -R 777 uploads output status
            
            echo "Starting container with $CPU_CORES CPU cores..."
            docker run -d \
              --name $CONTAINER_NAME \
              --cpus=$CPU_CORES \
              -p $PORT:8090 \
              -v "$(pwd)/uploads:/app/uploads" \
              -v "$(pwd)/output:/app/output" \
              -v "$(pwd)/status:/app/status" \
              --restart unless-stopped \
              $IMAGE_NAME
        fi
        
        # Check application status
        check_app_status
        ;;
        
    stop)
        echo "Stopping container..."
        docker stop $CONTAINER_NAME
        echo "Container stopped."
        ;;
        
    restart)
        echo "Stopping existing container..."
        docker stop $CONTAINER_NAME 2>/dev/null || true
        docker rm $CONTAINER_NAME 2>/dev/null || true
        
        echo "Building Docker image..."
        docker build -t $IMAGE_NAME .
        
        echo "Creating directories..."
        mkdir -p uploads output status
        chmod -R 777 uploads output status
        
        echo "Starting container with $CPU_CORES CPU cores..."
        docker run -d \
          --name $CONTAINER_NAME \
          --cpus=$CPU_CORES \
          -p $PORT:8090 \
          -v "$(pwd)/uploads:/app/uploads" \
          -v "$(pwd)/output:/app/output" \
          -v "$(pwd)/status:/app/status" \
          --restart unless-stopped \
          $IMAGE_NAME
          
        # Check application status
        check_app_status
        ;;
        
    status)
        if docker ps | grep -q $CONTAINER_NAME; then
            echo "Container is running. Checking application..."
            if curl -s http://localhost:$PORT -m 3 > /dev/null; then
                echo "✅ Application is accessible at http://localhost:$PORT"
                docker ps | grep $CONTAINER_NAME
            else
                echo "⚠️ Container is running but application is not accessible."
                echo "Container logs:"
                docker logs --tail 20 $CONTAINER_NAME
            fi
        else
            echo "Application is not running."
            if docker ps -a | grep -q $CONTAINER_NAME; then
                echo "Container exists but is not running. Use 'start' to start it."
            fi
        fi
        ;;
        
    *)
        show_usage
        ;;
esac

# # Run the script with the appropriate command
# chmod +x local-run.sh

# # Start the application
# ./local-run.sh start

# # Check status
# ./local-run.sh status

# # Restart (rebuild and restart)
# ./local-run.sh restart

# # Stop the application
# ./local-run.sh stop