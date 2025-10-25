"""
utils.py - Utility functions and helpers for the security scanner
"""
import os
import queue
from dotenv import load_dotenv

def load_config():
    """Load configuration from environment variables"""
    load_dotenv()

    config = {
        'SECRET_KEY': os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production'),
        'GEMINI_API_KEY': os.getenv('GEMINI_API_KEY', ''),
        'FLASK_DEBUG': os.getenv('FLASK_DEBUG', 'True').lower() == 'true',
        'MAX_SCAN_TIMEOUT': int(os.getenv('MAX_SCAN_TIMEOUT', '300')),
        'ENABLE_AI_ANALYSIS': os.getenv('ENABLE_AI_ANALYSIS', 'True').lower() == 'true'
    }

    return config

def setup_scan_queue():
    """Create and return a scan queue for inter-thread communication"""
    return queue.Queue()

def format_scan_output(output, severity='info'):
    """Format scan output with severity indicators"""
    severity_icons = {
        'critical': '🚨',
        'high': '🔴',
        'medium': '🟡',
        'low': '🟢',
        'info': 'ℹ️',
        'error': '❌',
        'success': '✅'
    }

    icon = severity_icons.get(severity, 'ℹ️')
    return f"{icon} {output}"

def validate_target(target):
    """Basic validation for scan targets"""
    if not target or not target.strip():
        return False, "Target cannot be empty"

    # Basic URL/IP validation
    import re
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

    if url_pattern.match(target) or ip_pattern.match(target):
        return True, "Valid target"
    else:
        return False, "Invalid target format. Use IP address or URL."

def get_file_size_mb(filepath):
    """Get file size in MB"""
    try:
        size_bytes = os.path.getsize(filepath)
        size_mb = size_bytes / (1024 * 1024)
        return round(size_mb, 2)
    except OSError:
        return 0

def cleanup_temp_files(directory, pattern="*.tmp"):
    """Clean up temporary files in a directory"""
    import glob
    try:
        temp_files = glob.glob(os.path.join(directory, pattern))
        for temp_file in temp_files:
            try:
                os.remove(temp_file)
            except OSError:
                pass  # Ignore errors when deleting temp files
    except Exception:
        pass  # Ignore errors during cleanup

def safe_filename(filename):
    """Create a safe filename by removing/replacing dangerous characters"""
    import re
    # Remove or replace dangerous characters
    safe_name = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing dots and spaces
    safe_name = safe_name.strip('. ')
    # Ensure it's not empty
    if not safe_name:
        safe_name = 'unnamed'
    return safe_name

def truncate_text(text, max_length=1000, suffix="..."):
    """Truncate text to a maximum length with optional suffix"""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix

def get_timestamp():
    """Get current timestamp in ISO format"""
    from datetime import datetime
    return datetime.now().isoformat()

def calculate_progress(current, total):
    """Calculate progress percentage"""
    if total == 0:
        return 0
    return min(100, int((current / total) * 100))