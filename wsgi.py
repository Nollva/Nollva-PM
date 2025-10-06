# wsgi.py
import sys
import os

# 🚨 CRITICAL FIX: HARDCODE CONFIGURATION HERE 🚨
# This bypasses the need for the missing 'dotenv' package.

# 1. SECRET KEY (CRITICAL: Insert your actual long, random string here)
os.environ['SECRET_KEY'] = 'd477e6d6acc65cd6822da6d30af0183b73f24e900c371f33a1cf97a8a1a38a81'

# 2. DATABASE PATH (Insert your file's ABSOLUTE path)
os.environ['DB_URI'] = 'mongodb+srv://djkolls:E8L2uvOOjBToSHGq@pmdatabase.rvzzb5u.mongodb.net/?retryWrites=true&w=majority&appName=PMDatabase' 

# 3. FLASK_ENV (Required)
os.environ['FLASK_ENV'] = 'production'

# 🚨 FIX 1: Add the project root directory
# This ensures Python can find 'server.py'
sys.path.insert(0, os.path.dirname(__file__))

# 🚨 FIX 2: FORCE ADD the virtual environment's site-packages path 🚨
# This ensures Python can find 'flask' and all other installed modules (like 'python-dotenv')
sys.path.insert(0, '/volume1/web/PM Web App/venv/lib/python3.8/site-packages')


# Import your Flask app instance (This is the final line)
from server import app as application