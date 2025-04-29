# api/index.py
# Vercel entry point

# Imports the 'app' instance from the main app.py file in the root directory
from app import app

# Vercel's runtime looks for the WSGI 'app' object.