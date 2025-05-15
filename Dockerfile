# Use lightweight Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy dependency file and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and rules
COPY app/ app/
COPY rules/ rules/

# Default command (overridden by Docker CLI if needed)
ENTRYPOINT ["python", "-m", "app.main"]
