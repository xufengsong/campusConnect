"""
ASGI config for backend project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os

import django
from django.core.asgi import get_asgi_application

from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')

# This is a critical step. It initializes Django's settings and application registry.
print("--- ASGI.PY: Initializing Django settings... ---")
django.setup()
print("--- ASGI.PY: Django setup complete. ---")

import api.routing
from api.middleware import WebSocketScopeLogger
from channels.security.websocket import OriginValidator

django_asgi_app = get_asgi_application()

# A simple custom middleware to log the connection scope
class ScopeLoggingMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        # We are only interested in WebSocket connections
        if scope['type'] == 'websocket':
            print("\n--- ASGI.PY SCOPE LOGGER ---")
            print(f"  Received WebSocket scope for path: {scope.get('path')}")
            print(f"  Client Host/Port: {scope.get('client')}")
            # To see all headers, uncomment the next line, but it can be very verbose.
            # print(f"  Headers: {scope.get('headers')}")
            print("--------------------------\n")
        
        # Pass the connection to the next layer in the stack
        return await self.app(scope, receive, send)

application = ProtocolTypeRouter({
    # Django's ASGI application to handle traditional HTTP requests
    "http": django_asgi_app,

    # WebSocket handler, now wrapped with our custom logger
    "websocket": OriginValidator(
        ScopeLoggingMiddleware(
            AuthMiddlewareStack(
                URLRouter(
                    api.routing.websocket_urlpatterns
                )
            ),
        ),
        [
            "https://upperlang.com",
            "https://www.upperlang.com",
            "http://localhost:8080",
        ],
    )
})

print("--- ASGI.PY: ProtocolTypeRouter configured. Application is ready. ---")