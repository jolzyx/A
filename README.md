# Authipy

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A secure and user-friendly 2FA (Two-Factor Authentication) code generator built with Python and PyQt5. Authipy helps you manage your two-factor authentication codes in a simple desktop application.

![Authipy Screenshot](docs/images/screenshot.png)

## 🚀 Features

- **TOTP Code Generation**: Generate time-based one-time passwords (TOTP) compatible with most 2FA services
- **QR Code Support**: Import accounts by scanning QR codes or display QR codes for easy transfer
- **Account Management**: 
  - Add, edit, and delete 2FA accounts
  - Recycle bin for deleted accounts
  - Support for custom issuer names
- **User-Friendly Interface**:
  - Clean and intuitive PyQt5-based GUI
  - Copy codes with a single click
  - Automatic code refresh
- **Security**:
  - Local storage only - your secrets never leave your device
  - Encrypted storage of authentication secrets
  - No internet connection required

## 📋 Requirements

- Python 3.8 or higher
- PyQt5
- Other dependencies are handled automatically during installation

## 🔧 Installation

### From PyPI (Recommended)

```bash
pip install authipy
```

### From Source

1. Clone the repository:
```bash
git clone https://github.com/TanmoyTheBoT/authipy.git
cd authipy
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install in development mode:
```bash
pip install -e .
```

## 🎮 Usage

### Launch the Application

```bash
authipy
```

Or if installed from source:
```bash
python -m authipy
```

### Adding a New Account

1. Click the "Add Account" button
2. Enter the required information:
   - Website/Service name
   - Secret key (provided by the service)
   - Issuer name (optional)
3. Click "Add" to save the account

### Generating Codes

1. Select an account from the list
2. The current TOTP code will be displayed automatically
3. Click the code to copy it to clipboard
4. A timer shows when the code will refresh

### Managing Accounts

- **Delete**: Right-click an account and select "Delete" or use the delete button
- **Restore**: Access the recycle bin from the menu to restore deleted accounts
- **QR Code**: Select an account and click "Show QR Code" to display/hide the QR code

## 🧪 Development

### Setting Up Development Environment

1. Install development dependencies:
```bash
pip install -r requirements-dev.txt
```

### Running Tests

```bash
pytest
```

For test coverage report:
```bash
pytest --cov=src --cov-report=html
```

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run the tests to ensure everything works
5. Commit your changes (`git commit -m 'Add some amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

Please make sure to update tests as appropriate and follow the existing code style.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [PyOTP](https://github.com/pyotp/pyotp) for TOTP implementation
- [PyQt5](https://www.riverbankcomputing.com/software/pyqt/) for the GUI framework
- [PyQRCode](https://github.com/mnooner256/pyqrcode) for QR code generation

## 📬 Contact

Tanmoy - [@TanmoyTheBoT](https://github.com/TanmoyTheBoT)

Project Link: [https://github.com/TanmoyTheBoT/authipy](https://github.com/TanmoyTheBoT/authipy)

## 📊 Project Status

This project is actively maintained and welcomes contributions. Check the [issues page](https://github.com/TanmoyTheBoT/authipy/issues) for feature requests and bug reports.
