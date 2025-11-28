"""
LLM Layer Package
Simulates LLM agents processing MCP tool responses to detect real prompt injection exploitation
"""

from mcp_security.llm.llm_simulator import LLMSimulator, LLMProvider, LLMExploitResult

__all__ = ["LLMSimulator", "LLMProvider", "LLMExploitResult"]
