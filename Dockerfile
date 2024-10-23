# Use the official Python image from the Docker Hub
FROM python:3.11.9

# Set environment variable to avoid output buffering
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire backend code into the container
COPY . .


COPY .env .env
# Expose port 8000 for the Django application



EXPOSE 8000

# Start the Django application using Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "Backend.wsgi:application", "--workers", "3"]
