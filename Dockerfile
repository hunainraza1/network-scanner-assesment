# Use Python 3.11 slim for a small and secure footprint
FROM python:3.11-slim

# Install system dependencies required for Scapy
RUN apt-get update && apt-get install -y \
    gcc \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your script
COPY scanner.py .

# Entrypoint allows Fares to pass the CIDR directly
ENTRYPOINT ["python", "scanner.py"]

# Default to help if no arguments are provided
CMD ["--help"]