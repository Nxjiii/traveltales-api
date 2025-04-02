# Lightweight Python base image
FROM python:3.9-slim

WORKDIR /app

# Install dependencies (cached unless requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only necessary files (excludes .venv/, etc.)
COPY . .

# Set environment variables
# Disable debug mode
ENV FLASK_APP=src/__init__.py
ENV FLASK_ENV=production  

EXPOSE 5000
CMD ["flask", "run", "--host=0.0.0.0"]