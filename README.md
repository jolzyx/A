# Authipy

Authipy is a desktop application built with PyQt5 for managing Time-based One-Time Password (TOTP) authentication codes. It allows users to securely store and manage TOTP secrets, generate QR codes for easy addition to authentication apps, and provides a recycle bin for deleted accounts.

## Features

- **Add and Manage Accounts**: Add accounts with their corresponding TOTP secrets.
- **QR Code Generation**: Generate and display QR codes for easy addition to mobile authentication apps.
- **Recycle Bin**: Restore accidentally deleted accounts from the recycle bin.
- **Clipboard Copy**: Copy the generated TOTP code to the clipboard with a single click.
- **Export and Import Accounts**: Export accounts to a JSON file and import them back when needed.
- **Encryption**: Securely store secrets using Fernet symmetric encryption.

## Prerequisites

Ensure you have the following installed:
- Python 3.6+
- PyQt5
- pyotp
- pyqrcode
- cryptography

You can install the required packages using pip:
```sh
pip install pyqt5 pyotp pyqrcode cryptography
