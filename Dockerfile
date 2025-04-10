FROM python:3.9-slim

# Install required Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create work directory
WORKDIR /app

# Copy application files
COPY app.py .
RUN mkdir -p templates static uploads status data
COPY templates/ templates/
COPY static/ static/

# Set permissions
RUN chmod +x app.py

# Expose the application port
EXPOSE 8091

# Set default command to use Gunicorn with increased timeout and gevent worker
CMD ["gunicorn", "--bind", "0.0.0.0:8091", "--workers", "4", "--timeout", "300", "--worker-class", "gevent", "--worker-connections", "1000", "app:app"] 