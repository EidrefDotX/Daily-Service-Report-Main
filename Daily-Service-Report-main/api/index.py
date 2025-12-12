import os
import sys

# Ensure the app is importable when the function runs on Vercel
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from app import create_app  # noqa: E402

# Vercel's Python runtime looks for a module-level WSGI `app`
app = create_app()

