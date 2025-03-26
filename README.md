# Authipy

<div align="center">

[![Test PyPI](https://img.shields.io/badge/dynamic/json?label=test.pypi&query=%24.info.version&url=https%3A%2F%2Ftest.pypi.org%2Fpypi%2FAuthipy%2Fjson&prefix=v)](https://test.pypi.org/project/Authipy/)
[![PyPI Version](https://img.shields.io/pypi/v/Authipy.svg)](https://pypi.org/project/Authipy)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/github/license/TanmoyTheBoT/authipy.svg)](LICENSE)
[![Downloads](https://img.shields.io/github/downloads/TanmoyTheBoT/authipy/total.svg)](https://github.com/TanmoyTheBoT/authipy/releases)

A secure, offline Two-Factor Authentication (2FA) desktop application.

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Contributing](#contributing)

<img src="https://raw.githubusercontent.com/TanmoyTheBoT/Authipy/master/docs/images/screenshot.png" alt="Authipy Screenshot" width="400">

</div>

## Features

- 🔒 Secure TOTP code generation
- 💾 Local-only storage
- 📱 QR code import/export
- 🗑️ Recycle bin feature
- 📋 One-click copying
- ⚡ Modern Qt interface

## Installation

### Method 1: Windows Executable (Recommended)
1. Download the latest `Authipy.exe` from [Releases](https://github.com/TanmoyTheBoT/authipy/releases)
2. Run directly - No installation required

### Method 2: PyPI Package
```bash
pip install authipy
authipy  # to run
```

### Method 3: Build from Source

1. Clone the repository:
```bash
git clone https://github.com/TanmoyTheBoT/authipy.git
cd authipy
```

2. Create and activate virtual environment (recommended):
```bash
python -m venv venv
venv\\Scripts\\activate   # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install in development mode:
```bash
pip install -e .
```

5. Run the application:
```bash
authipy
```

6. Build executable (optional):
```bash
# Install PyInstaller
pip install pyinstaller Pillow sip

# Build single-file executable
pyinstaller --clean --noconsole --onefile --icon=docs/images/test.jpg --name Authipy src/authipy/main.py
```

The executable will be created in the `dist` directory.

## Usage

### Add New Account
1. Click "Add Account"
2. Enter:
   - Service name (required)
   - Secret key (required)
   - Issuer name (optional)

### Generate Codes
- Select account from list
- Code displays automatically
- Click code to copy

### Manage Accounts
- Right-click for options
- Use recycle bin
- Import/Export accounts

### Data Location
- Windows: `%USERPROFILE%\.config\authipy`
- Offline storage only

## Contributing

1. Fork the repository
2. Install dev dependencies:
```bash
pip install -r requirements-dev.txt
```
3. Make changes
4. Run tests:
```bash
pytest
pytest --cov=src --cov-report=html  # coverage report
```
5. Submit Pull Request

## Support

- [Report Issues](https://github.com/TanmoyTheBoT/authipy/issues)
- [GitHub Repository](https://github.com/TanmoyTheBoT/authipy)

## License

[MIT License](LICENSE)

---
<div align="center">
<sub>Built with ❤️ by <a href="https://github.com/TanmoyTheBoT">TanmoyTheBoT</a></sub>
</div>