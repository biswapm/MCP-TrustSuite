# Contributing to MCP Security Testing Framework

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Remember this is for authorized security testing only
- Report security vulnerabilities responsibly

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists
2. Create a detailed bug report including:
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - Environment details (OS, Python version)
   - Log output (if applicable)

### Suggesting Features

1. Check if the feature has been requested
2. Describe the feature and its use case
3. Explain how it improves security testing
4. Consider security implications

### Submitting Code

1. **Fork the repository**
2. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Write your code:**
   - Follow PEP 8 style guide
   - Add docstrings to functions and classes
   - Include type hints where appropriate
   - Write tests for new functionality

4. **Test your changes:**
   ```bash
   pytest tests/
   python -m flake8 mcp_security/
   python -m mypy mcp_security/
   ```

5. **Commit your changes:**
   ```bash
   git commit -m "Add: Brief description of changes"
   ```
   
   Commit message prefixes:
   - `Add:` New features
   - `Fix:` Bug fixes
   - `Update:` Updates to existing features
   - `Docs:` Documentation changes
   - `Test:` Test additions or updates
   - `Refactor:` Code refactoring

6. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/MCP-Security.git
cd MCP-Security

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Run tests
pytest tests/ -v
```

## Code Style

- Follow PEP 8
- Use meaningful variable names
- Keep functions focused and small
- Add comments for complex logic
- Use type hints

Example:
```python
async def test_vulnerability(
    self,
    target: str,
    payload: str,
    timeout: int = 30
) -> VulnerabilityResult:
    """
    Test a specific vulnerability
    
    Args:
        target: Target endpoint to test
        payload: Payload to use in test
        timeout: Request timeout in seconds
        
    Returns:
        VulnerabilityResult with test outcome
    """
    # Implementation
    pass
```

## Adding New Attack Vectors

To add a new prompt injection attack:

1. Add payload to `attacks/prompt_injection_impl.py`:
```python
InjectionPayload(
    name="Your Attack Name",
    type=InjectionType.YOUR_TYPE,
    payload="your payload here",
    description="What this attack does",
    severity="high"
)
```

2. Update documentation
3. Add tests
4. Update CHANGELOG.md

## Adding New Penetration Tests

To add a new penetration test:

1. Add test to `attacks/pentest.py`:
```python
async def test_your_vulnerability(self, test: VulnerabilityTest) -> PentestResult:
    """Test for your vulnerability"""
    # Implementation
    pass
```

2. Register in `_load_tests()`
3. Add documentation
4. Add tests
5. Update CHANGELOG.md

## Testing Guidelines

- Write tests for all new features
- Ensure tests are isolated and repeatable
- Mock external dependencies
- Test both success and failure cases
- Aim for >80% code coverage

## Documentation

- Update README.md for new features
- Add docstrings to all public APIs
- Update QUICKSTART.md if user-facing
- Include examples for complex features

## Security Considerations

- Never commit real credentials or secrets
- Test on authorized systems only
- Follow responsible disclosure for vulnerabilities
- Consider security implications of new features

## Pull Request Process

1. Update documentation
2. Add tests
3. Update CHANGELOG.md
4. Ensure all tests pass
5. Request review from maintainers
6. Address review feedback
7. Squash commits if requested

## Questions?

Open an issue with the `question` label for help.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
