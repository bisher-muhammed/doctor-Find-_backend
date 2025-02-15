# FindDoctor - Django Backend

FindDoctor is a Django-based backend for an online doctor consultation platform. It provides authentication, user and doctor management, real-time chat, video call integration, payment processing, and appointment scheduling.

## Features

- **JWT Authentication** for secure access control.
- **Email OTP Verification** for user registration.
- **Admin Panel** for managing users and doctors.
- **Doctor Profiles** with availability slots.
- **Real-time Chat** using Python SocketIO.
- **Video Call Integration** with Ziggo Cloud.
- **Payment Integration** with Razorpay.
- **Containerized** using Docker for easy deployment.

## Installation

### Prerequisites

- Python (>=3.x)
- Django (latest version)
- PostgreSQL (or Psql for development)
- Docker (optional, for containerized deployment)

### Setup Instructions

1. Clone the repository:
   ```sh
   git clone https://github.com/bisher-muhammed/doctor-Find-_backend.git
   cd doctor-Find-_backend
   ```
2. Create a virtual environment:
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
4. Apply database migrations:
   ```sh
   python manage.py migrate
   ```
5. Create a superuser:
   ```sh
   python manage.py createsuperuser
   ```
6. Run the development server:
   ```sh
   python manage.py runserver
   ```

## Running with Docker

1. Build and start the container:
   ```sh
   docker-compose up --build
   ```
2. Stop the container:
   ```sh
   docker-compose down
   ```






