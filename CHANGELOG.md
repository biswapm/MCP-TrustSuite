# Changelog

All notable changes to the MCP Security Testing Framework will be documented in this file.

## [0.1.0] - 2025-11-20

### Added
- Initial release of MCP Security Testing Framework
- MCP client for connecting to remote MCP servers
- Comprehensive prompt injection testing module with 14+ attack vectors
- Penetration testing module with 10+ vulnerability tests
- Automated security scanner with full and quick scan modes
- CLI interface with commands for scan, inject, pentest, and discover
- Rich reporting in JSON and text formats
- Example scripts and configurations
- Complete documentation

### Features
- **Prompt Injection Tests:**
  - Context breaking
  - Instruction override
  - Role manipulation
  - Payload encoding (base64, unicode)
  - System prompt extraction
  - Chain-of-thought exploitation
  - Delimiter manipulation
  - Token smuggling

- **Penetration Tests:**
  - Authentication testing
  - Authorization bypass detection
  - Input validation (SQL injection, XXE)
  - Path traversal detection
  - Command injection testing
  - Rate limiting checks
  - Resource exhaustion testing
  - Information disclosure detection

- **Security Scanner:**
  - Full comprehensive scans
  - Quick security assessments
  - Tool-specific vulnerability testing
  - Risk level assessment
  - Detailed reporting

- **CLI Commands:**
  - `scan` - Full security scanning
  - `inject` - Prompt injection testing
  - `pentest` - Penetration testing
  - `discover` - Server discovery

### Security Considerations
- All testing requires proper authorization
- Designed for ethical security testing only
- Includes responsible disclosure guidelines

## [Future Releases]

### Planned Features
- HTML report generation
- Advanced fuzzing capabilities
- Machine learning-based anomaly detection
- Integration with popular security tools
- WebSocket support for MCP servers
- Custom plugin system for additional tests
- Performance testing capabilities
- Compliance reporting (OWASP, CWE)
