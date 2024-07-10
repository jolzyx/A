import sys
import json
import pyotp
import pyqrcode
import time
import os
import base64
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, 
    QListWidget, QListWidgetItem, QMessageBox, QMenu, QAction, QMainWindow, QFileDialog
)
from PyQt5.QtGui import QPixmap, QFont, QCursor
from PyQt5.QtCore import QTimer, Qt

KEY_FILE = 'secret.enc'
ACCOUNTS_FILE = 'accounts.json'
RECYCLE_BIN_FILE = 'recycle_bin.json'

class CipherManager:
    def __init__(self, key_file):
        self.key_file = key_file
        self.key = self.loadKey()
        self.cipher = Fernet(self.key)

    def loadKey(self):
        """
        Load the encryption key from the specified key file.
        If the file doesn't exist, generate a new key and save it.
        """
        try:
            with open(self.key_file, 'rb') as key_file:
                return key_file.read()
        except FileNotFoundError:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as key_file:
                key_file.write(key)
            return key

    def encrypt(self, data):
        """
        Encrypt the provided data using Fernet symmetric encryption.
        """
        return self.cipher.encrypt(data.encode())

    def decrypt(self, data):
        """
        Decrypt the provided data using Fernet symmetric encryption.
        """
        return self.cipher.decrypt(data).decode()

class RecycleBinWindow(QWidget):
    def __init__(self, recycle_bin, cipher_manager, restore_callback):
        super().__init__()
        self.recycle_bin = recycle_bin
        self.cipher_manager = cipher_manager
        self.restore_callback = restore_callback
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Recycle Bin')

        mainLayout = QVBoxLayout()

        self.recycle_bin_list = QListWidget(self)
        self.updateRecycleBinList()
        mainLayout.addWidget(self.recycle_bin_list)

        self.restore_button = QPushButton('Restore', self)
        self.restore_button.clicked.connect(self.restoreAccount)
        mainLayout.addWidget(self.restore_button)

        self.setLayout(mainLayout)

    def updateRecycleBinList(self):
        self.recycle_bin_list.clear()
        for website in self.recycle_bin:
            self.recycle_bin_list.addItem(QListWidgetItem(website))

    def restoreAccount(self):
        current_item = self.recycle_bin_list.currentItem()
        if current_item:
            website = current_item.text()
            reply = QMessageBox.question(self, 'Restore Account', f"Are you sure you want to restore the account for {website}?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.restore_callback(website)
                self.updateRecycleBinList()

class AuthipyApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.cipher_manager = CipherManager(KEY_FILE)
        self.accounts = {}
        self.recycle_bin = {}

        self.initUI()
        self.loadAccounts()
        self.loadRecycleBin()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.updateCodes)
        self.timer.start(1000)

    def initUI(self):
        self.setWindowTitle('Authipy')

        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)

        mainLayout = QVBoxLayout()
        inputLayout = QHBoxLayout()

        self.website_input = QLineEdit(self)
        self.website_input.setPlaceholderText('Website Name')
        inputLayout.addWidget(self.website_input)

        self.secret_input = QLineEdit(self)
        self.secret_input.setPlaceholderText('Secret Code')
        inputLayout.addWidget(self.secret_input)

        self.add_button = QPushButton('Add', self)
        self.add_button.clicked.connect(self.addAccount)
        inputLayout.addWidget(self.add_button)

        mainLayout.addLayout(inputLayout)

        self.accounts_list = QListWidget(self)
        self.accounts_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.accounts_list.customContextMenuRequested.connect(self.showContextMenu)
        self.accounts_list.itemClicked.connect(self.onAccountSelected)
        mainLayout.addWidget(self.accounts_list)

        codeLayout = QHBoxLayout()
        
        self.code_label = QLabel('Your Code:', self)
        codeLayout.addWidget(self.code_label)

        self.code_display = QLabel('------', self)
        self.code_display.setAlignment(Qt.AlignCenter)
        self.code_display.setCursor(QCursor(Qt.PointingHandCursor))
        self.code_display.mousePressEvent = self.copyCodeToClipboard
        codeLayout.addWidget(self.code_display)

        mainLayout.addLayout(codeLayout)

        self.timer_label = QLabel('Time left:', self)
        mainLayout.addWidget(self.timer_label)

        self.qr_label = QLabel(self)
        mainLayout.addWidget(self.qr_label)

        self.show_qr_button = QPushButton('Show QR Code', self)
        self.show_qr_button.clicked.connect(self.toggleQRCode)
        self.show_qr_button.setEnabled(False)
        mainLayout.addWidget(self.show_qr_button)

        self.main_widget.setLayout(mainLayout)
        self.setStyle()

        # Create menu bar
        menubar = self.menuBar()
        task_menu = menubar.addMenu('Task')

        recycle_bin_action = QAction('Recycle Bin', self)
        recycle_bin_action.triggered.connect(self.openRecycleBin)
        task_menu.addAction(recycle_bin_action)

        export_action = QAction('Export', self)
        export_action.triggered.connect(self.exportAccounts)
        task_menu.addAction(export_action)

        import_action = QAction('Import', self)
        import_action.triggered.connect(self.importAccounts)
        task_menu.addAction(import_action)

    def setStyle(self):
        self.setStyleSheet("""
            QWidget {
                font-family: Arial;
                font-size: 14px;
            }
            QPushButton {
                padding: 5px;
            }
            QLineEdit {
                padding: 5px;
            }
            QListWidget {
                padding: 5px;
            }
            QLabel {
                padding: 5px;
            }
        """)
        self.code_label.setFont(QFont("Arial", 16, QFont.Bold))
        self.code_display.setFont(QFont("Arial", 20, QFont.Bold))
        self.timer_label.setFont(QFont("Arial", 12))

    def is_valid_base32(self, secret):
        try:
            base64.b32decode(secret, casefold=True)
            return True
        except Exception:
            return False

    def addAccount(self):
        website = self.website_input.text().strip()
        secret = self.secret_input.text().strip()
        if not website or not secret:
            QMessageBox.warning(self, 'Input Error', 'Both website and secret code are required.')
            return

        if website in self.accounts:
            QMessageBox.warning(self, 'Duplicate Account', 'This website already exists.')
            return

        if not self.is_valid_base32(secret):
            QMessageBox.warning(self, 'Invalid Secret', 'The secret code format is invalid.')
            return

        # Check for duplicate secret keys
        for account_secret in self.accounts.values():
            if self.cipher_manager.decrypt(account_secret) == secret:
                QMessageBox.warning(self, 'Duplicate Secret', 'This secret key already exists for another account.')
                return

        self.accounts[website] = self.cipher_manager.encrypt(secret)
        self.updateAccountList()
        self.website_input.clear()
        self.secret_input.clear()
        self.saveAccounts()

    def updateAccountList(self):
        self.accounts_list.clear()
        for website in self.accounts:
            self.accounts_list.addItem(QListWidgetItem(website))

    def onAccountSelected(self, item):
        self.show_qr_button.setEnabled(True)
        self.qr_label.clear()  # Clear QR code display when switching accounts
        self.show_qr_button.setText('Show QR Code')
        self.updateCodes()

    def toggleQRCode(self):
        if self.qr_label.pixmap():
            self.qr_label.clear()
            self.show_qr_button.setText('Show QR Code')
        else:
            self.showQRCode()
            self.show_qr_button.setText('Hide QR Code')

    def showQRCode(self):
        current_item = self.accounts_list.currentItem()
        if current_item:
            website = current_item.text()
            secret = self.cipher_manager.decrypt(self.accounts[website])
            totp = pyotp.TOTP(secret)
            url = totp.provisioning_uri(name=website, issuer_name="Authipy")
            qr = pyqrcode.create(url)
            qr_filename = f'{website}_qrcode.png'
            try:
                qr.png(qr_filename, scale=5)
                pixmap = QPixmap(qr_filename)
                self.qr_label.setPixmap(pixmap)
                os.remove(qr_filename)  # Remove the temporary QR code image file
            except Exception as e:
                QMessageBox.critical(self, 'QR Code Error', f'Failed to generate QR code: {e}')

    def updateCodes(self):
        current_item = self.accounts_list.currentItem()
        if current_item:
            website = current_item.text()
            secret = self.cipher_manager.decrypt(self.accounts[website])
            totp = pyotp.TOTP(secret)
            self.updateCode(totp)

    def updateCode(self, totp):
        self.code_display.setText(totp.now())
        time_left = 30 - (int(time.time()) % 30)
        self.timer_label.setText(f'Time left: {time_left}s')

    def copyCodeToClipboard(self, event):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.code_display.text())

    def showContextMenu(self, pos):
        current_item = self.accounts_list.itemAt(pos)
        if current_item:
            menu = QMenu(self)
            delete_action = QAction('Delete', self)
            delete_action.triggered.connect(lambda: self.deleteAccount(current_item.text()))
            menu.addAction(delete_action)
            menu.exec_(self.accounts_list.mapToGlobal(pos))

    def deleteAccount(self, website):
        if website in self.accounts:
            reply = QMessageBox.question(self, 'Delete Account', f"Are you sure you want to delete the account for {website}?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.recycle_bin[website] = self.accounts[website]
                del self.accounts[website]
                self.updateAccountList()
                self.qr_label.clear()  # Clear QR code display when deleting an account
                self.show_qr_button.setText('Show QR Code')
                self.show_qr_button.setEnabled(False)
                self.saveAccounts()
                self.saveRecycleBin()

    def restoreAccount(self, website):
        if website in self.recycle_bin:
            self.accounts[website] = self.recycle_bin[website]
            del self.recycle_bin[website]
            self.updateAccountList()
            self.saveAccounts()
            self.saveRecycleBin()

    def saveAccounts(self):
        with open(ACCOUNTS_FILE, 'w') as file:
            encrypted_accounts = {website: secret.decode() for website, secret in self.accounts.items()}
            json.dump(encrypted_accounts, file)

    def loadAccounts(self):
        try:
            with open(ACCOUNTS_FILE, 'r') as file:
                content = file.read().strip()
                if content:
                    encrypted_accounts = json.loads(content)
                    self.accounts = {website: secret.encode() for website, secret in encrypted_accounts.items()}
                    self.updateAccountList()
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def saveRecycleBin(self):
        with open(RECYCLE_BIN_FILE, 'w') as file:
            encrypted_recycle_bin = {website: secret.decode() for website, secret in self.recycle_bin.items()}
            json.dump(encrypted_recycle_bin, file)

    def loadRecycleBin(self):
        try:
            with open(RECYCLE_BIN_FILE, 'r') as file:
                content = file.read().strip()
                if content:
                    encrypted_recycle_bin = json.loads(content)
                    self.recycle_bin = {website: secret.encode() for website, secret in encrypted_recycle_bin.items()}
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def openRecycleBin(self):
        self.recycle_bin_window = RecycleBinWindow(self.recycle_bin, self.cipher_manager, self.restoreAccount)
        self.recycle_bin_window.show()

    def exportAccounts(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getSaveFileName(self, "Export Accounts", "", "JSON Files (*.json);;All Files (*)", options=options)
        if fileName:
            with open(fileName, 'w') as file:
                encrypted_accounts = {website: secret.decode() for website, secret in self.accounts.items()}
                json.dump(encrypted_accounts, file)
            QMessageBox.information(self, 'Export Successful', 'Accounts have been exported successfully.')

    def importAccounts(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self, "Import Accounts", "", "JSON Files (*.json);;All Files (*)", options=options)
        if fileName:
            with open(fileName, 'r') as file:
                imported_accounts = json.load(file)
                for website, secret in imported_accounts.items():
                    self.accounts[website] = secret.encode()
            self.updateAccountList()
            self.saveAccounts()
            QMessageBox.information(self, 'Import Successful', 'Accounts have been imported successfully.')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = AuthipyApp()
    ex.show()
    sys.exit(app.exec_())
