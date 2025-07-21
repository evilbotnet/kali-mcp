# Use Python slim image for Apple Silicon
FROM --platform=linux/arm64 python:3.11-slim

# Set working directory
WORKDIR /app

# Install git to clone repository and clean up in same layer
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Clone Kali Tools documentation repository
RUN git clone https://gitlab.com/kalilinux/documentation/kali-tools.git kali-tools-data

# Copy our MCP server files
COPY server.py .

# Set unbuffered Python output
ENV PYTHONUNBUFFERED=1

# Default command for MCP server
CMD ["python", "/app/server.py"]