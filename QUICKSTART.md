# MCP Security Testing - Quick Start Guide

## Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd MCP-Security
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Install the package (optional):**
```bash
pip install -e .
```

## Command Line Usage

### 1. Full Security Scan
Scan an MCP server for all vulnerabilities:
```bash
python -m mcp_security scan --url http://localhost:3000
```

### 2. Quick Scan
Run a fast security assessment:
```bash
python -m mcp_security scan --url http://localhost:3000 --quick
```

### 3. Prompt Injection Testing
Test a specific tool for prompt injection:
```bash
python -m mcp_security inject --url http://localhost:3000 --tool search --parameter query
```

### 4. Penetration Testing
Run comprehensive penetration tests:
```bash
python -m mcp_security pentest --url http://localhost:3000
```

### 5. Server Discovery
Discover available tools and resources:
```bash
python -m mcp_security discover --url http://localhost:3000
```

### Advanced Options

**Custom output location:**
```bash
python -m mcp_security scan --url http://localhost:3000 -o reports/my_scan.json
```

**Text format report:**
```bash
python -m mcp_security scan --url http://localhost:3000 -f txt
```

**Skip specific tests:**
```bash
python -m mcp_security scan --url http://localhost:3000 --no-prompt-injection
python -m mcp_security scan --url http://localhost:3000 --no-pentest
```

**Verbose output:**
```bash
python -m mcp_security scan --url http://localhost:3000 -v
```

## Python API Usage

### Basic Scan
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

### Prompt Injection Testing
```python
import asyncio
from mcp_security.client.mcp_client_impl import MCPClient
from mcp_security.attacks.prompt_injection_impl import PromptInjector

async def main():
    client = MCPClient(base_url="http://localhost:3000")
    await client.connect()
    
    injector = PromptInjector(client)
    results = await injector.test_tool("search", "query")
    report = injector.generate_report(results)
    
    print(f"Block Rate: {report['summary']['block_rate']}")
    
    await client.close()

asyncio.run(main())
```

### Penetration Testing
```python
import asyncio
from mcp_security.client.mcp_client_impl import MCPClient
from mcp_security.attacks.pentest import PenetrationTester

async def main():
    client = MCPClient(base_url="http://localhost:3000")
    await client.connect()
    
    tester = PenetrationTester(client)
    results = await tester.run_all_tests()
    report = tester.generate_report(results)
    
    print(f"Vulnerabilities: {report['summary']['vulnerabilities_found']}")
    
    await client.close()

asyncio.run(main())
```

## Configuration File

Create a `config.yaml` file:
```yaml
target:
  url: "http://localhost:3000"
  timeout: 30

tests:
  prompt_injection:
    enabled: true
  penetration_testing:
    enabled: true

reporting:
  format: "json"
  output_dir: "reports/"
```

See `config.example.yaml` for full configuration options.

## Examples

Run the example scripts:

```bash
# Basic security scan
python examples/basic_scan.py

# Prompt injection testing
python examples/prompt_injection_test.py

# Penetration testing
python examples/penetration_test.py

# Custom workflow
python examples/custom_workflow.py
```

## Understanding Results

### Risk Levels
- **CRITICAL**: Immediate action required, severe vulnerabilities found
- **HIGH**: Significant security issues detected
- **MEDIUM**: Moderate security concerns
- **LOW**: Minor issues or potential risks
- **MINIMAL**: No significant vulnerabilities found

### Prompt Injection Results
- **Block Rate**: Percentage of injection attempts that were blocked
- Higher block rate = better security

### Penetration Test Results
- **Security Score**: Percentage of tests passed
- Higher score = better security

## Common Use Cases

### 1. CI/CD Integration
```bash
python -m mcp_security scan --url $MCP_SERVER_URL -o reports/scan.json
# Check exit code and parse JSON report
```

### 2. Regular Security Audits
```bash
# Weekly full scan
python -m mcp_security scan --url http://production-server:3000 -o reports/weekly_$(date +%Y%m%d).json
```

### 3. Development Testing
```bash
# Quick check during development
python -m mcp_security scan --url http://localhost:3000 --quick
```

## Troubleshooting

### Connection Issues
```bash
# Test basic connectivity
curl http://localhost:3000/mcp/v1/tools/list
```

### SSL Certificate Errors
Add `--no-verify-ssl` flag or set `verify_ssl: false` in config

### Authentication
Add custom headers in config or via environment variables:
```yaml
target:
  headers:
    Authorization: "Bearer ${API_TOKEN}"
```

## Best Practices

1. **Always get authorization** before testing production systems
2. **Start with quick scans** to verify connectivity
3. **Review reports carefully** - automated tools may have false positives
4. **Test regularly** as part of your security workflow
5. **Keep the tool updated** for latest attack vectors

## Getting Help

```bash
# View all commands
python -m mcp_security --help

# View command-specific help
python -m mcp_security scan --help
python -m mcp_security inject --help
```

## Next Steps

- Review the full `README.md` for detailed documentation
- Check out example scripts in `examples/` directory
- Customize tests using the Python API
- Integrate into your CI/CD pipeline
