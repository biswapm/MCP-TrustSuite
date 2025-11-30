#!/usr/bin/env python3
"""
Azure App Service startup script for MCP-TrustSuite
"""
import os
import sys

# Add the application directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

# Get port from environment (Azure sets this)
port = int(os.environ.get('PORT', 8000))

# Import and run the web UI
from mcp_security.web_ui import app

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=port)
