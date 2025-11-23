
FROM python:3.10-slim

# Set environment
ENV PYTHONUNBUFFERED=1
WORKDIR /app

# Install system deps required by some Python packages (matplotlib, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libfreetype6-dev \
    libpng-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install (leverage Docker cache)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy static assets first (if present) to leverage caching
COPY static/ /app/static/

# Copy application code
COPY . /app

# Ensure static directory exists
RUN mkdir -p /app/static

# Expose port
EXPOSE 8000

# Run the uvicorn server
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
