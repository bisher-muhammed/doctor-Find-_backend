# asgi.py
import os
import django
from django.core.asgi import get_asgi_application
from .sockets import sio  # Import Socket.IO from the separate file
import socketio

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Backend.settings')

django.setup()

# Django ASGI application
django_asgi_app = get_asgi_application()

# Combine Django ASGI app with Socket.IO
application = socketio.ASGIApp(sio, django_asgi_app)
