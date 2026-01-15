#!/bin/bash
echo "[INFO] Starting TraceX Web Dashboard..."
cd "$(dirname "$0")"

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 could not be found"
    exit 1
fi

# Install dependencies
echo "[INFO] Checking dependencies..."
pip3 install -r backend/requirements.txt

# Start the server
echo "[INFO] Server running at http://localhost:8000"
export PYTHONPATH=..:$PYTHONPATH
python3 backend/main.py