"""
MCP Security Testing Framework
A comprehensive framework for testing MCP server security
"""

__version__ = "0.1.0"
__author__ = "MCP Security Team"

from mcp_security.client.mcp_client import MCPClient
from mcp_security.scanner.security_scanner import SecurityScanner
from mcp_security.attacks.prompt_injection import PromptInjector
from mcp_security.attacks.pentest import PenetrationTester

__all__ = [
    "MCPClient",
    "SecurityScanner",
    "PromptInjector",
    "PenetrationTester",
]
