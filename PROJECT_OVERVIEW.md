# MCP Security Testing Framework - Project Overview

## 📁 Project Structure

```
MCP-Security/
├── mcp_security/              # Main package
│   ├── __init__.py           # Package initialization
│   ├── __main__.py           # Entry point for python -m
│   ├── cli.py                # Command-line interface
│   ├── client/               # MCP client implementation
│   │   ├── __init__.py
│   │   ├── mcp_client.py     # Client interface
│   │   └── mcp_client_impl.py # Client implementation
│   ├── attacks/              # Attack modules
│   │   ├── __init__.py
│   │   ├── prompt_injection.py       # Prompt injection interface
│   │   ├── prompt_injection_impl.py  # 14+ injection payloads
│   │   └── pentest.py                # 10+ penetration tests
│   ├── scanner/              # Security scanner
│   │   ├── __init__.py
│   │   ├── security_scanner.py       # Scanner interface
│   │   └── security_scanner_impl.py  # Scanner implementation
│   └── utils/                # Utility functions
│       ├── __init__.py
│       └── helpers.py
│
├── examples/                 # Example scripts
│   ├── basic_scan.py
│   ├── prompt_injection_test.py
│   ├── penetration_test.py
│   └── custom_workflow.py
│
├── tests/                    # Test suite
│   ├── __init__.py
│   └── test_basic.py
│
├── reports/                  # Output directory for reports
│   └── .gitkeep
│
├── logs/                     # Log files directory
│   └── .gitkeep
│
├── README.md                 # Main documentation
├── QUICKSTART.md            # Quick start guide
├── CHANGELOG.md             # Version history
├── CONTRIBUTING.md          # Contribution guidelines
├── LICENSE                  # MIT License
├── requirements.txt         # Python dependencies
├── setup.py                 # Package setup
├── config.example.yaml      # Example configuration
└── .gitignore              # Git ignore rules
```

## 🎯 Core Features

### 1. MCP Client (`client/`)
- Async HTTP client for MCP protocol
- Support for tools, resources, and prompts
- Configurable timeout and SSL verification
- Comprehensive error handling

### 2. Prompt Injection Testing (`attacks/prompt_injection_impl.py`)
**14+ Attack Vectors:**
- Context Breaking
- Instruction Override
- Role Manipulation
- Payload Encoding (Base64, Unicode)
- System Prompt Extraction
- Chain-of-Thought Exploitation
- Delimiter Manipulation
- Token Smuggling

### 3. Penetration Testing (`attacks/pentest.py`)
**10+ Vulnerability Tests:**
- Authentication Bypass
- Authorization Flaws
- SQL Injection
- XXE (XML External Entity)
- Path Traversal
- Command Injection
- Rate Limiting
- Resource Exhaustion
- Information Disclosure

### 4. Security Scanner (`scanner/`)
**Scan Types:**
- Full Scan: Comprehensive security assessment
- Quick Scan: Fast vulnerability check
- Tool-Specific Scan: Target individual tools

**Features:**
- Automated tool discovery
- Parallel test execution
- Risk level assessment
- Multiple report formats (JSON, TXT)

### 5. CLI Interface (`cli.py`)
**Commands:**
- `scan` - Run security scans
- `inject` - Test prompt injection
- `pentest` - Run penetration tests
- `discover` - Discover server capabilities

## 🚀 Quick Start

### Installation
```bash
pip install -r requirements.txt
```

### Basic Usage
```bash
# Full scan
python -m mcp_security scan --url http://localhost:3000

# Quick scan
python -m mcp_security scan --url http://localhost:3000 --quick

# Prompt injection test
python -m mcp_security inject --url http://localhost:3000 --tool search --parameter query

# Penetration test
python -m mcp_security pentest --url http://localhost:3000

# Discovery
python -m mcp_security discover --url http://localhost:3000
```

### Python API
```python
import asyncio
from mcp_security.scanner.security_scanner_impl import SecurityScanner

async def main():
    scanner = SecurityScanner(base_url="http://localhost:3000")
    await scanner.initialize()
    results = await scanner.run_full_scan()
    scanner.save_report(results, "report.json")
    await scanner.cleanup()

asyncio.run(main())
```

## 📊 Report Structure

### JSON Report Format
```json
{
  "scan_id": "20251120_143022",
  "target": "http://localhost:3000",
  "timestamp": "2025-11-20T14:30:22",
  "summary": {
    "risk_level": "MEDIUM",
    "total_vulnerabilities": 5,
    "critical_vulnerabilities": 0,
    "high_vulnerabilities": 2
  },
  "prompt_injection": {
    "summary": {
      "total_tests": 14,
      "injections_blocked": 10,
      "injections_succeeded": 4,
      "block_rate": "71.4%"
    }
  },
  "penetration_testing": {
    "summary": {
      "total_tests": 10,
      "vulnerabilities_found": 1,
      "security_score": "90.0%"
    }
  }
}
```

## 🔐 Security Features

### Detection Mechanisms
- Response analysis for suspicious content
- Error message inspection
- Status code evaluation
- Header analysis
- Payload effectiveness tracking

### Severity Levels
- **CRITICAL**: Immediate action required
- **HIGH**: Significant security risk
- **MEDIUM**: Moderate concern
- **LOW**: Minor issue

### Risk Assessment
Automated risk scoring based on:
- Number of vulnerabilities
- Severity distribution
- Attack surface analysis
- Response patterns

## 🧪 Testing Strategy

### Test Coverage
- Unit tests for core components
- Integration tests for workflows
- Mock-based testing for external dependencies
- Async test support with pytest-asyncio

### Example Test Execution
```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=mcp_security --cov-report=html

# Run specific test
pytest tests/test_basic.py::TestMCPClient -v
```

## 📈 Performance

### Optimization Features
- Async/await for concurrent operations
- Connection pooling with httpx
- Configurable timeouts
- Rate limiting awareness
- Efficient payload delivery

### Scalability
- Parallel test execution
- Streaming results
- Incremental reporting
- Memory-efficient processing

## 🔧 Configuration

### Config File Options
```yaml
target:
  url: "http://localhost:3000"
  timeout: 30
  verify_ssl: true
  headers:
    Authorization: "Bearer token"

tests:
  prompt_injection:
    enabled: true
    test_types: [...]
  
  penetration_testing:
    enabled: true
    test_types: [...]

reporting:
  format: "json"
  output_dir: "reports/"
```

## 🤝 Contributing

See `CONTRIBUTING.md` for:
- Code style guidelines
- Development setup
- Testing requirements
- Pull request process
- Security considerations

## 📝 Documentation

- **README.md**: Complete project documentation
- **QUICKSTART.md**: Fast getting started guide
- **CHANGELOG.md**: Version history
- **CONTRIBUTING.md**: Contribution guidelines
- **Examples**: Working code examples

## ⚠️ Legal & Ethical Use

**IMPORTANT:** This tool is for authorized security testing only.

- Always obtain proper authorization
- Test only systems you own or have permission to test
- Follow responsible disclosure practices
- Comply with applicable laws and regulations
- Use for defensive security purposes

## 📦 Dependencies

### Core
- `httpx` - Async HTTP client
- `pydantic` - Data validation
- `click` - CLI framework
- `rich` - Terminal formatting
- `pyyaml` - Configuration parsing

### Development
- `pytest` - Testing framework
- `black` - Code formatting
- `flake8` - Linting
- `mypy` - Type checking

## 🎓 Learning Resources

### Understanding MCP
- Model Context Protocol documentation
- MCP server implementations
- Security best practices

### Security Testing
- OWASP Testing Guide
- Prompt injection research
- API security testing

## 🚧 Future Roadmap

- HTML report generation
- WebSocket support
- Advanced fuzzing
- ML-based detection
- Plugin system
- Performance testing
- Compliance reporting

## 📄 License

MIT License - See LICENSE file for details

## 🙏 Acknowledgments

Built for the security research community to help secure MCP implementations.

---

**Version:** 0.1.0  
**Status:** Initial Release  
**Last Updated:** 2025-11-20
