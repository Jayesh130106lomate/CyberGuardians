"""
app.py - Main Flask application entry point
"""
from flask import Flask
import logging
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import our modules
from utils import load_config, setup_scan_queue
from models import SecurityScanner
from routes import register_routes
from ai_analyzer import AISecurityAnalyzer

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)

    # Load configuration
    config = load_config()
    app.config.update(config)

    # Setup scan queue for inter-thread communication
    app.config['scan_queue'] = setup_scan_queue()

    # Initialize AI analyzer if API key is available
    ai_analyzer = None
    if config['GEMINI_API_KEY']:
        ai_analyzer = AISecurityAnalyzer(config['GEMINI_API_KEY'])

    # Register all routes
    register_routes(app, ai_analyzer)

    return app

# Create the application instance
app = create_app()

if __name__ == '__main__':
    # Suppress Flask development server warning
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    print("="*50)
    print("  🛡️  Security Scanner Pro with AI")
    print("="*50)
    if app.config.get('GEMINI_API_KEY'):
        print("  ✓ AI Analysis: Enabled")
    else:
        print("  ✗ AI Analysis: Disabled (Set GEMINI_API_KEY)")
    print("="*50)

    app.run(
        debug=app.config.get('FLASK_DEBUG', True),
        host='0.0.0.0',
        port=5000,
        threaded=True
    )