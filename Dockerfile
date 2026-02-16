FROM python:3.9-slim

# Install Java (required for ZAP) and wget
RUN apt-get update && apt-get install -y \
    openjdk-17-jre-headless \
    wget \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Set up workspace
WORKDIR /app

# Install OWASP ZAP
ENV ZAP_VERSION=2.14.0
RUN wget -q https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz \
    && tar -xzf ZAP_${ZAP_VERSION}_Linux.tar.gz \
    && mv ZAP_${ZAP_VERSION} /opt/zap \
    && rm ZAP_${ZAP_VERSION}_Linux.tar.gz

# Add ZAP to PATH
ENV PATH=$PATH:/opt/zap

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port (Render uses PORT env var)
ENV PORT=10000
EXPOSE $PORT

# Grant execution permission to start script
RUN chmod +x start.sh

# Start the application
CMD ["./start.sh"]
