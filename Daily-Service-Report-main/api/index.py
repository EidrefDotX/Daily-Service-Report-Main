import os
import sys

# Add parent directory to path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Import and create app
from app import create_app

# Vercel requires the Flask app to be named 'app'
# The @vercel/python runtime automatically uses this WSGI app
app = create_app()
