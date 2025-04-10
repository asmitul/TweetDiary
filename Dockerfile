FROM python:3.9-slim

# Install required system dependencies
RUN apt-get update && apt-get install -y \
    poppler-utils \
    imagemagick \
    ghostscript \
    && rm -rf /var/lib/apt/lists/*

# Configure ImageMagick policy to allow PDF processing
RUN sed -i 's/rights="none" pattern="PDF"/rights="read|write" pattern="PDF"/' /etc/ImageMagick-6/policy.xml

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create work directory
WORKDIR /app

# Copy application files
COPY pdf_to_image.py .
COPY app.py .
RUN mkdir -p templates static uploads output status
COPY templates/ templates/
COPY static/ static/

# Create directory structure
RUN chmod +x pdf_to_image.py app.py

# Expose the non-standard port
EXPOSE 8090

# Set default command to use Gunicorn with increased timeout and gevent worker
CMD ["gunicorn", "--bind", "0.0.0.0:8090", "--workers", "4", "--timeout", "300", "--worker-class", "gevent", "--worker-connections", "1000", "app:app"] 