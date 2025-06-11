"""
WSGI config for Discord Bot Web Panel.

This module contains the WSGI application used by the web server to serve the
Flask application.
"""
import os
import sys
from pathlib import Path

# Add the project directory to the Python path
project_root = str(Path(__file__).parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import the application
from keep_alive import main

# Create application object to be used by gunicorn
application = main()

if __name__ == "__main__":
    # Run the application directly if this file is executed
    # (useful for development)
    main()
