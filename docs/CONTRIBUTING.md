# Contributing to RedClouds

Thank you for your interest in contributing to RedClouds! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/rfs85/redclouds/issues)
2. If not, create a new issue with:
   - Clear title describing the issue
   - Detailed description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)
   - Screenshots if applicable

### Suggesting Enhancements

1. Check existing [Issues](https://github.com/rfs85/redclouds/issues) for similar suggestions
2. Create a new issue with:
   - Clear title describing the enhancement
   - Detailed description of the proposed feature
   - Use cases and benefits
   - Any potential implementation details

### Pull Requests

1. Fork the repository
2. Create a new branch (`git checkout -b feature/AmazingFeature`)
3. Make your changes
4. Run tests (`python -m pytest`)
5. Update documentation
6. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
7. Push to your branch (`git push origin feature/AmazingFeature`)
8. Open a Pull Request

## Development Setup

1. Clone your fork:
   ```bash
   git clone https://github.com/your-username/redclouds.git
   cd redclouds
   ```

2. Set up virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # or `venv\Scripts\activate` on Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

## Coding Standards

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use type hints for function arguments and return values
- Write docstrings for all public functions and classes
- Keep functions focused and single-purpose
- Add comments for complex logic

## Testing

- Write unit tests for new features
- Ensure all tests pass before submitting PR
- Maintain or improve code coverage
- Test edge cases and error conditions

### Running Tests
```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=redclouds

# Run specific test file
python -m pytest tests/test_specific.py
```

## Documentation

- Update README.md for user-facing changes
- Update docstrings for API changes
- Add examples for new features
- Keep documentation clear and concise

## Git Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor" not "Moves cursor")
- Reference issues and pull requests
- Keep first line under 72 characters
- Describe what and why, not how

Example:
```
Add S3 bucket encryption check

- Implement check for default encryption
- Add documentation for new check
- Include unit tests

Fixes #123
```

## Release Process

1. Update version in `setup.py`
2. Update CHANGELOG.md
3. Create release notes
4. Tag release in git
5. Push to PyPI

## Questions?

Feel free to:
- Open an issue for questions
- Join our [Discord community](https://discord.gg/redclouds)
- Contact maintainers directly

## License

By contributing, you agree that your contributions will be licensed under the MIT License. 