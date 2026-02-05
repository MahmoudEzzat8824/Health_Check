#!/usr/bin/env python3
"""
Server Health Check Web Application
Flask-based web service for running server health checks
"""

import os
import subprocess
import re
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps
from collections import defaultdict
import threading
from flask import Flask, render_template, request, jsonify, send_from_directory, session, abort
from werkzeug.utils import secure_filename
from werkzeug.security import safe_join

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Configuration
UPLOAD_FOLDER = Path('uploads')
RESULTS_FOLDER = Path('results')
ALLOWED_EXTENSIONS = {'txt'}
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB
MAX_SERVERS_PER_FILE = 100  # Limit servers per file
MAX_SERVER_NAME_LENGTH = 255
SESSION_TIMEOUT = 3600  # 1 hour
MAX_REQUESTS_PER_MINUTE = 10

# Create necessary directories
UPLOAD_FOLDER.mkdir(exist_ok=True)
RESULTS_FOLDER.mkdir(exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['RESULTS_FOLDER'] = RESULTS_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'  # HTTPS only in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = SESSION_TIMEOUT

# Rate limiting storage
rate_limit_storage = defaultdict(list)
rate_limit_lock = threading.Lock()


def get_client_id():
    """Generate anonymous client identifier without storing IP"""
    # Use session-based identification instead of IP
    if 'client_id' not in session:
        session['client_id'] = secrets.token_hex(16)
    return session['client_id']


def rate_limit(max_requests=MAX_REQUESTS_PER_MINUTE):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_id = get_client_id()
            now = datetime.now()
            
            with rate_limit_lock:
                # Clean old requests
                rate_limit_storage[client_id] = [
                    req_time for req_time in rate_limit_storage[client_id]
                    if now - req_time < timedelta(minutes=1)
                ]
                
                # Check rate limit
                if len(rate_limit_storage[client_id]) >= max_requests:
                    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
                
                # Add current request
                rate_limit_storage[client_id].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response


def allowed_file(filename):
    """Check if file has allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_server_file(filepath):
    """Validate server file format with security checks"""
    try:
        # Check file size
        file_size = os.path.getsize(filepath)
        if file_size > MAX_FILE_SIZE:
            return False, "File size exceeds maximum allowed"
        
        # Read with size limit
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines(1024 * 1024)  # Max 1MB
        
        servers = []
        # Regex for basic hostname/IP validation
        hostname_pattern = re.compile(
            r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        )
        ip_pattern = re.compile(
            r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Validate length
            if len(line) > MAX_SERVER_NAME_LENGTH:
                return False, f"Server name too long on line {line_num}"
            
            # Check for suspicious characters
            if any(char in line for char in ['|', ';', '&', '`', '$', '(', ')', '<', '>', '\\']):
                return False, f"Invalid characters in server name on line {line_num}"
            
            # Validate format (hostname or IP)
            if not (hostname_pattern.match(line) or ip_pattern.match(line)):
                return False, f"Invalid server format on line {line_num}: {line[:50]}"
            
            servers.append(line)
        
        if not servers:
            return False, "No valid server entries found in file"
        
        if len(servers) > MAX_SERVERS_PER_FILE:
            return False, f"Too many servers. Maximum allowed: {MAX_SERVERS_PER_FILE}"
        
        return True, f"Found {len(servers)} server(s)"
    except UnicodeDecodeError:
        return False, "Invalid file encoding. Please use UTF-8 text file"
    except Exception as e:
        return False, "Error validating file"


@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')


@app.route('/api/upload', methods=['POST'])
@rate_limit(max_requests=5)  # More restrictive for upload endpoint
def upload_file():
    """Handle file upload and initiate health check"""
    
    # Validate request
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    if 'username' not in request.form:
        return jsonify({'error': 'No username provided'}), 400
    
    file = request.files['file']
    username = request.form['username'].strip()
    
    # Sanitize and validate username
    if not username:
        return jsonify({'error': 'Username cannot be empty'}), 400
    
    # Only allow alphanumeric, underscore, and hyphen
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return jsonify({'error': 'Username contains invalid characters'}), 400
    
    if len(username) > 32:
        return jsonify({'error': 'Username too long (max 32 characters)'}), 400
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Only .txt files are allowed'}), 400
    
    try:
        # Generate unique job ID using session-based approach
        job_id = secrets.token_urlsafe(16)
        session_job_ids = session.get('job_ids', [])
        session_job_ids.append(job_id)
        session['job_ids'] = session_job_ids[-10:]  # Keep last 10 jobs only
        
        # Save uploaded file with secure name
        filename = secure_filename(file.filename)
        if not filename:
            filename = 'servers.txt'
        upload_path = app.config['UPLOAD_FOLDER'] / f"{job_id}_{filename}"
        
        # Ensure path is within upload folder (prevent path traversal)
        if not str(upload_path.resolve()).startswith(str(app.config['UPLOAD_FOLDER'].resolve())):
            return jsonify({'error': 'Invalid file path'}), 400
        
        file.save(upload_path)
        os.chmod(upload_path, 0o600)  # Owner read/write only
        
        # Validate file content
        is_valid, message = validate_server_file(upload_path)
        if not is_valid:
            upload_path.unlink()  # Delete invalid file
            return jsonify({'error': message}), 400
        
        # Run health check script
        script_path = Path(__file__).parent / 'server_health_check.sh'
        
        if not script_path.exists():
            return jsonify({'error': 'Health check script not found'}), 500
        
        # Create result file
        result_file = app.config['RESULTS_FOLDER'] / f"{job_id}_result.txt"
        
        # Execute the script
        try:
            # Make script executable
            os.chmod(script_path, 0o755)
            
            # Run the script and capture output
            result = subprocess.run(
                [str(script_path), '-f', str(upload_path), '-u', username],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            # Sanitize output - remove any potential sensitive info
            def sanitize_output(text):
                """Remove sensitive information from output"""
                # Remove absolute paths
                text = re.sub(r'/[a-zA-Z0-9/_.-]+(?=\s|$)', '[PATH]', text)
                # Remove potential SSH keys or tokens
                text = re.sub(r'-----BEGIN [A-Z ]+-----[^-]+-----END [A-Z ]+-----', '[REDACTED]', text, flags=re.DOTALL)
                # Remove API keys or tokens
                text = re.sub(r'[a-zA-Z0-9_-]{32,}', '[TOKEN]', text)
                return text
            
            # Combine stdout and stderr with sanitization
            output = f"=== Server Health Check Results ===\n"
            output += f"Job ID: {job_id}\n"
            output += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            output += f"Status: {'Success' if result.returncode == 0 else 'Completed with errors'}\n"
            output += f"\n{'=' * 50}\n\n"
            
            if result.stdout:
                output += "=== STDOUT ===\n"
                output += sanitize_output(result.stdout) + "\n\n"
            
            if result.stderr:
                output += "=== STDERR ===\n"
                output += sanitize_output(result.stderr) + "\n\n"
            
            if result.returncode != 0:
                output += f"\n=== Script exited with code: {result.returncode} ===\n"
            
            # Save results
            with open(result_file, 'w') as f:
                f.write(output)
            
            # Clean up uploaded file securely
            try:
                upload_path.unlink()
            except Exception:
                pass  # File already deleted or doesn't exist
            
            return jsonify({
                'success': True,
                'job_id': job_id,
                'message': message,
                'output': output,
                'exit_code': result.returncode
            })
            
        except subprocess.TimeoutExpired:
            # Clean up on timeout
            try:
                upload_path.unlink()
            except Exception:
                pass
            return jsonify({'error': 'Health check timed out (5 minutes limit)'}), 500
        except Exception:
            # Clean up on error
            try:
                upload_path.unlink()
            except Exception:
                pass
            return jsonify({'error': 'Script execution failed'}), 500
    
    except Exception:
        return jsonify({'error': 'Request processing failed'}), 500


@app.route('/api/download/<job_id>')
@rate_limit()
def download_result(job_id):
    """Download result file - only for jobs created in this session"""
    # Verify job belongs to current session
    session_job_ids = session.get('job_ids', [])
    if job_id not in session_job_ids:
        abort(403)  # Forbidden - not your job
    
    # Sanitize job_id
    safe_job_id = secure_filename(job_id)
    result_file = f"{safe_job_id}_result.txt"
    
    # Use safe_join to prevent path traversal
    try:
        safe_path = safe_join(str(app.config['RESULTS_FOLDER']), result_file)
        result_path = Path(safe_path)
    except Exception:
        abort(400)  # Bad request
    
    # Verify path is within results folder
    if not str(result_path.resolve()).startswith(str(app.config['RESULTS_FOLDER'].resolve())):
        abort(400)
    
    if not result_path.exists():
        return jsonify({'error': 'Result file not found'}), 404
    
    return send_from_directory(
        app.config['RESULTS_FOLDER'],
        result_file,
        as_attachment=True,
        download_name=f"health_check_results.txt"
    )


@app.route('/health')
def health():
    """Health check endpoint - no sensitive data"""
    return jsonify({'status': 'ok'})


def cleanup_old_files():
    """Cleanup old upload and result files"""
    try:
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        for folder in [UPLOAD_FOLDER, RESULTS_FOLDER]:
            for file_path in folder.glob('*'):
                if file_path.is_file():
                    file_time = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if file_time < cutoff_time:
                        file_path.unlink()
    except Exception:
        pass  # Silent fail for cleanup


# Cleanup old files on startup
cleanup_old_files()


if __name__ == '__main__':
    # Development server - disable debug in production!
    app.run(debug=False, host='0.0.0.0', port=5000)
