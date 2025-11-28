# 📚 Documentation Index

Welcome to the MCP Security Testing Framework documentation!

## 🚀 Getting Started

1. **[QUICKSTART.md](QUICKSTART.md)** - Get up and running in 5 minutes
   - Installation instructions
   - Basic usage examples
   - Common commands
   - Troubleshooting

2. **[README.md](README.md)** - Complete project documentation
   - Detailed feature overview
   - Full API reference
   - Configuration options
   - Security considerations

## 📖 Core Documentation

### Usage Guides
- **[QUICKSTART.md](QUICKSTART.md)** - Fast start guide
- **[README.md](README.md)** - Full documentation
- **[config.example.yaml](config.example.yaml)** - Configuration template


### Technical Documentation
- **[PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)** - Architecture and design
- **[CHANGELOG.md](CHANGELOG.md)** - Version history
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Development guide

## 🎯 Quick Reference

### CLI Commands

```bash
# Full scan
python -m mcp_security scan --url http://localhost:3000

# Quick scan
python -m mcp_security scan --url http://localhost:3000 --quick

# Prompt injection
python -m mcp_security inject --url http://localhost:3000 --tool TOOL --parameter PARAM

# Penetration test
python -m mcp_security pentest --url http://localhost:3000

# Discovery
python -m mcp_security discover --url http://localhost:3000
```

### Python API

```python
# Security Scanner
from mcp_security.scanner.security_scanner_impl import SecurityScanner

scanner = SecurityScanner(base_url="http://localhost:3000")
await scanner.initialize()
results = await scanner.run_full_scan()
await scanner.cleanup()

# Prompt Injection
from mcp_security.attacks.prompt_injection_impl import PromptInjector

injector = PromptInjector(client)
results = await injector.test_tool("tool_name", "parameter_name")

# Penetration Testing
from mcp_security.attacks.pentest import PenetrationTester

tester = PenetrationTester(client)
results = await tester.run_all_tests()
```

## 🔍 Feature Documentation

### Prompt Injection (14+ Attack Vectors)
- Context Breaking
- Instruction Override
- Role Manipulation
- Payload Encoding
- System Prompt Extraction
- Chain-of-Thought
- Delimiter Manipulation
- Token Smuggling

### Penetration Testing (10+ Tests)
- Authentication Bypass
- Authorization Flaws
- SQL Injection
- XXE Vulnerabilities
- Path Traversal
- Command Injection
- Rate Limiting
- Resource Exhaustion
- Information Disclosure

## 🤝 Contributing

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for:
- Code style guidelines
- Development setup
- Testing requirements
- Pull request process

## 📄 License

MIT License - See **[LICENSE](LICENSE)** file

## ⚠️ Important Legal Notice

**This tool is for authorized security testing only.**

Always:
- ✅ Obtain proper authorization
- ✅ Test only authorized systems
- ✅ Follow responsible disclosure
- ✅ Comply with laws and regulations
- ✅ Use for defensive security

Never:
- ❌ Test without permission
- ❌ Use for malicious purposes
- ❌ Violate terms of service
- ❌ Access unauthorized systems

## 📞 Support

- **Issues**: Open a GitHub issue
- **Questions**: Create a discussion
- **Security**: Follow responsible disclosure

## 🗂️ File Structure

```
MCP-Security/
├── README.md                 ← Main documentation
├── QUICKSTART.md            ← Quick start guide
├── PROJECT_OVERVIEW.md      ← Architecture details
├── CONTRIBUTING.md          ← Developer guide
├── CHANGELOG.md             ← Version history
├── LICENSE                  ← MIT License
│
├── mcp_security/            ← Source code
│   ├── client/              ← MCP client
│   ├── attacks/             ← Attack modules
│   ├── scanner/             ← Security scanner
│   ├── utils/               ← Utilities
│   └── cli.py               ← CLI interface
│
├── examples/                ← Usage examples
├── tests/                   ← Test suite
├── reports/                 ← Output reports
└── logs/                    ← Log files
```

## 🎓 Learning Path

### Beginners
1. Read [QUICKSTART.md](QUICKSTART.md)
2. Run `python -m mcp_security scan --url YOUR_URL --quick`
3. Try examples in `examples/` directory
4. Explore CLI commands with `--help`

### Intermediate
1. Read [README.md](README.md) fully
2. Create custom test configurations
3. Use Python API for scripting
4. Integrate into CI/CD pipelines

### Advanced
1. Read [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)
2. Contribute new attack vectors
3. Extend with custom modules
4. See [CONTRIBUTING.md](CONTRIBUTING.md)

## 🔗 Quick Links

| Document | Purpose | Audience |
|----------|---------|----------|
| [README.md](README.md) | Complete documentation | All users |
| [QUICKSTART.md](QUICKSTART.md) | Fast start guide | New users |
| [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) | Technical details | Developers |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development guide | Contributors |
| [CHANGELOG.md](CHANGELOG.md) | Version history | All users |

---

**Need help?** Start with [QUICKSTART.md](QUICKSTART.md) or open an issue!
