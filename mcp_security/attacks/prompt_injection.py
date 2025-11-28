"""Attack modules for MCP security testing"""
from mcp_security.attacks.prompt_injection_impl import PromptInjector, InjectionType, InjectionPayload, InjectionResult

__all__ = ["PromptInjector", "InjectionType", "InjectionPayload", "InjectionResult"]
