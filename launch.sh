#!/bin/bash
# Launch script for MCP Security Testing Framework (Linux/Mac)

echo ""
echo "==================================================================="
echo "  MCP Security Testing Framework"
echo "  Linux/Mac Launcher"
echo "==================================================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3.9 or higher"
    exit 1
fi

# Check if dependencies are installed
python3 -c "import fastapi" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing dependencies..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to install dependencies"
        exit 1
    fi
fi

# Run the launcher
python3 launch.py
