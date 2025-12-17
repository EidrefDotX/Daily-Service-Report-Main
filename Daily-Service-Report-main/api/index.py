import os
import sys
import json

# Add parent directory to path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Import and create app
from app import create_app

# WSGI middleware to fix path for Vercel serverless
class VercelPathMiddleware:
    """
    Middleware to fix PATH_INFO for Vercel Python serverless functions.
    
    When Vercel routes requests to /api/index.py, the original path is lost.
    This middleware restores it from Vercel's headers or SCRIPT_NAME.
    """
    def __init__(self, app):
        self.app = app
    
    def __call__(self, environ, start_response):
        current_path = environ.get('PATH_INFO', '/')
        script_name = environ.get('SCRIPT_NAME', '')
        
        # Special debug endpoint - returns all environ vars
        if current_path == '/__vercel_debug__' or script_name.endswith('/__vercel_debug__'):
            response_body = json.dumps({
                "PATH_INFO": current_path,
                "SCRIPT_NAME": script_name,
                "REQUEST_URI": environ.get('REQUEST_URI', ''),
                "RAW_URI": environ.get('RAW_URI', ''),
                "HTTP_X_MATCHED_PATH": environ.get('HTTP_X_MATCHED_PATH', ''),
                "HTTP_X_INVOKE_PATH": environ.get('HTTP_X_INVOKE_PATH', ''),
                "HTTP_X_ORIGINAL_URL": environ.get('HTTP_X_ORIGINAL_URL', ''),
                "HTTP_X_FORWARDED_HOST": environ.get('HTTP_X_FORWARDED_HOST', ''),
                "HTTP_X_VERCEL_FORWARDED_FOR": environ.get('HTTP_X_VERCEL_FORWARDED_FOR', ''),
                "HTTP_HOST": environ.get('HTTP_HOST', ''),
                "all_http_headers": {k: v for k, v in environ.items() if k.startswith('HTTP_')},
                "all_keys": list(environ.keys()),
            }, indent=2).encode('utf-8')
            
            start_response('200 OK', [
                ('Content-Type', 'application/json'),
                ('Content-Length', str(len(response_body)))
            ])
            return [response_body]
        
        # The key insight: In Vercel, SCRIPT_NAME often contains the actual path
        # and PATH_INFO is just "/" or the handler path
        
        # Case 1: SCRIPT_NAME has the real path (most common in Vercel)
        if script_name and script_name not in ['', '/', '/api', '/api/index', '/api/index.py']:
            # SCRIPT_NAME contains the original path, move it to PATH_INFO
            environ['PATH_INFO'] = script_name
            environ['SCRIPT_NAME'] = ''
        
        # Case 2: PATH_INFO is the handler path, check headers for original
        elif current_path in ['/api/index.py', '/api/index', '/index.py', '/index', '/']:
            # Try various Vercel headers
            for header in ['HTTP_X_INVOKE_PATH', 'HTTP_X_MATCHED_PATH', 'HTTP_X_ORIGINAL_URL', 'RAW_URI', 'REQUEST_URI']:
                value = environ.get(header, '')
                if value and value not in ['/api/index.py', '/api/index', '/index.py', '/index', '/', '']:
                    # Extract just the path part
                    if header in ['HTTP_X_ORIGINAL_URL', 'RAW_URI', 'REQUEST_URI']:
                        value = value.split('?')[0]  # Remove query string
                    if value.startswith('/'):
                        environ['PATH_INFO'] = value
                        break
        
        return self.app(environ, start_response)


# Create the Flask app
flask_app = create_app()

# Add a debug route to check what path Flask receives
@flask_app.route('/__debug__')
def debug_route():
    from flask import request, jsonify
    return jsonify({
        "path": request.path,
        "url": request.url,
        "full_path": request.full_path,
        "script_root": request.script_root,
        "url_root": request.url_root,
        "headers": dict(request.headers),
        "environ_path_info": request.environ.get('PATH_INFO'),
        "environ_script_name": request.environ.get('SCRIPT_NAME'),
        "environ_raw_uri": request.environ.get('RAW_URI'),
    })

# Add a catch-all route for debugging (will show what path Flask receives)
@flask_app.route('/api/<path:subpath>')
def api_catchall(subpath):
    from flask import request, jsonify
    return jsonify({
        "error": "Route not found",
        "received_path": request.path,
        "subpath": subpath,
        "hint": "Flask received this path but couldn't match it"
    }), 404

# Wrap with middleware for Vercel
# Vercel requires the WSGI app to be named 'app'
app = VercelPathMiddleware(flask_app)
