class DebugUserMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Print the user for every single request that comes in
        print(f"Path: {request.path}, User: {request.user}")
        
        response = self.get_response(request)
        return response
    

class WebSocketScopeLogger:
    """
    This middleware prints the scope of every WebSocket connection attempt.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'websocket':
            print("--- INCOMING WEBSOCKET CONNECTION ---")
            # Print the path to see if it's what you expect
            print(f"Path: {scope.get('path')}")
            # Print headers to confirm the origin and host
            headers = {h[0].decode(): h[1].decode() for h in scope.get('headers', [])}
            print(f"Host: {headers.get('host')}")
            print(f"Origin: {headers.get('origin')}")
            print("------------------------------------")
        
        return await self.app(scope, receive, send)