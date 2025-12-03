import json
from channels.generic.websocket import AsyncWebsocketConsumer
from urllib.parse import parse_qs
from channels.db import database_sync_to_async

class NotificationConsumer(AsyncWebsocketConsumer):
    
    @database_sync_to_async
    def get_user_from_session(self, session_key):
        """
        Retrieve the user from a session key.
        This is needed for cross-origin WebSocket connections where cookies aren't sent.
        """
        # Import here to avoid AppRegistryNotReady error
        from django.contrib.auth.models import AnonymousUser
        from django.contrib.sessions.models import Session
        from django.contrib.auth import get_user_model
        
        User = get_user_model()
        
        try:
            session = Session.objects.get(session_key=session_key)
            uid = session.get_decoded().get('_auth_user_id')
            if uid:
                return User.objects.get(pk=uid)
        except (Session.DoesNotExist, User.DoesNotExist):
            pass
        return AnonymousUser()
    
    async def connect(self):
        print(f"WebSocket connect attempt by user: {self.scope['user']}")
        
        # Check if user is already authenticated via scope (same-origin)
        user = self.scope["user"]
        
        # If user is anonymous, try to get session from query parameters (cross-origin)
        if user.is_anonymous:
            query_string = self.scope.get('query_string', b'').decode()
            query_params = parse_qs(query_string)
            # Changed 'session' to 'token' to match frontend
            token = query_params.get('token', [None])[0]
            
            print(f"Token from query params: {token}")
            
            if token:
                user = await self.get_user_from_session(token)
                # Update the scope with the authenticated user
                self.scope['user'] = user
                print(f"User authenticated via token: {user}")
        
        # Now check if user is authenticated
        if self.scope["user"].is_anonymous:
            print("Connection REJECTED: User is anonymous.")
            await self.close()
        else:
            print(f"Connection ACCEPTED for user: {self.scope['user']}.")
            # Create a unique group name for each user
            self.group_name = f'user_{self.scope["user"].id}'
            
            # Add this user's channel to the group
            await self.channel_layer.group_add(
                self.group_name,
                self.channel_name
            )
            await self.accept()

    async def disconnect(self, close_code):
        # Remove the channel from the group when disconnected
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(
                self.group_name,
                self.channel_name
            )

    # This handles incoming messages from the client, like the heartbeat.
    async def receive(self, text_data):
        data = json.loads(text_data)
        # Gracefully handle the 'ping' from the frontend and ignore it.
        if data.get('type') == 'ping':
            pass  # Or you can print("Ping received") for debugging

    # This method is called when a message is sent to the user's group
    async def task_notification(self, event):
        # Send the message down to the client
        await self.send(text_data=json.dumps({
            'type': event['type'],
            'message': event['message']
        }))

    # Handles the message with the full data payload
    async def task_result(self, event):
        await self.send(text_data=json.dumps({
            'type': 'result',
            'data': event['data']
        }))