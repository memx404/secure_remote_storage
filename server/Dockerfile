# Base Image: Python 3.10 Slim
# Selected for minimal footprint and compatibility with cryptography wheels.
FROM python:3.10-slim

# Set working directory for the application
WORKDIR /app

# Install dependencies
# Copied first to optimize Docker layer caching during rebuilds.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Initialize storage directory structure
RUN mkdir -p server/storage

# Expose API port
EXPOSE 5000

# Entrypoint: Execute the server package as a module
CMD ["python", "-m", "server.app"]
