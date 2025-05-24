FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements files and install dependencies
COPY tests/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Set Python path to include the project root
ENV PYTHONPATH=/app

# Run tests
CMD ["python3", "-m", "unittest", "discover", "tests", "-v"]
