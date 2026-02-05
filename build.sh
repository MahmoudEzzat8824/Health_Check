#!/usr/bin/env bash
# Render.com build script

# Exit on error
set -o errexit

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn

# Create necessary directories
mkdir -p uploads results

# Make script executable
chmod +x server_health_check.sh

echo "✅ Build completed successfully"
