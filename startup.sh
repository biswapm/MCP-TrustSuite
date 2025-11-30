#!/bin/bash
# Azure App Service startup script for MCP-TrustSuite

echo "Starting MCP-TrustSuite Web UI..."

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Start the web UI server
python -m mcp_security.web_ui
