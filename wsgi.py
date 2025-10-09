#!/usr/bin/python3
import sys
import site
import os
from dotenv import load_dotenv # <-- NEW IMPORT

# --- Load Environment Variables FIRST ---
# Define the path to your .env file
dotenv_path = '/opt/Nollva_PM_App/.env'
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

# --- VIRTUAL ENVIRONMENT ACTIVATION ---
# Get the path to your venv's site-packages directory
# Adjust python3.X to your exact Python version (e.g., python3.13)
site.addsitedir('/opt/Nollva_PM_App/.venv/lib/python3.13/site-packages')

# Add your application directory to the Python path
sys.path.insert(0, '/opt/Nollva_PM_App')

# Import the main Flask object (it's named 'app' inside 'server.py')
from server import app as application