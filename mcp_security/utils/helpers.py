"""
Utility functions for MCP Security Testing
"""

import re
import base64
import hashlib
from typing import Any, Dict, List, Optional


def encode_base64(text: str) -> str:
    """Encode text to base64"""
    return base64.b64encode(text.encode()).decode()


def decode_base64(text: str) -> str:
    """Decode base64 text"""
    try:
        return base64.b64decode(text).decode()
    except Exception:
        return ""


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to be safe for file system"""
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Limit length
    if len(filename) > 200:
        filename = filename[:200]
    return filename


def calculate_hash(data: str) -> str:
    """Calculate SHA256 hash of data"""
    return hashlib.sha256(data.encode()).hexdigest()


def truncate_text(text: str, max_length: int = 100) -> str:
    """Truncate text to maximum length"""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."


def extract_urls(text: str) -> List[str]:
    """Extract URLs from text"""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text)


def is_suspicious_response(response_text: str) -> bool:
    """Check if response contains suspicious content"""
    suspicious_keywords = [
        "password", "secret", "api_key", "token", "credential",
        "root:", "uid=", "gid=", "/etc/passwd", "administrator",
        "system prompt", "internal instruction", "debug mode"
    ]
    
    text_lower = response_text.lower()
    return any(keyword in text_lower for keyword in suspicious_keywords)


def format_severity(severity: str) -> str:
    """Format severity with color codes for terminal"""
    colors = {
        "critical": "\033[91m",  # Red
        "high": "\033[93m",      # Yellow
        "medium": "\033[94m",    # Blue
        "low": "\033[92m",       # Green
    }
    reset = "\033[0m"
    
    color = colors.get(severity.lower(), "")
    return f"{color}{severity.upper()}{reset}"


def parse_json_response(text: str) -> Optional[Dict[str, Any]]:
    """Safely parse JSON from response text"""
    import json
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
