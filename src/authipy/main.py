import sys
import json
import pyotp
import pyqrcode
import time
import os
import pyperclip
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, 
    QListWidget, QListWidgetItem, QMessageBox, QMenu, QAction, QMainWindow, QFileDialog
)
from PyQt5.QtGui import QPixmap, QFont, QCursor, QIcon
from PyQt5.QtCore import QTimer, Qt

CONFIG_DIR = os.path.join(os.path.expanduser('~'), '.config', 'authipy')
if not os.path.exists(CONFIG_DIR):
    os.makedirs(CONFIG_DIR)

ACCOUNTS_FILE = os.path.join(CONFIG_DIR, 'accounts.json')
RECYCLE_BIN_FILE = os.path.join(CONFIG_DIR, 'recycle_bin.json')

class RecycleBinWindow(QWidget):
    def __init__(self, recycle_bin, restore_callback):
        super().__init__()
        self.recycle_bin = recycle_bin
        self.restore_callback = restore_callback
        self.initUI()
        self.setStyle()

    def setStyle(self):
        self.setStyleSheet("""
            QWidget {
                font-family: 'Segoe UI', Arial;
                font-size: 14px;
                background-color: #f5f5f5;
            }
            QListWidget {
                border: 1px solid #BDBDBD;
                border-radius: 4px;
                background-color: white;
                padding: 5px;
                margin: 5px 0;
            }
            QListWidget::item {
                padding: 8px;
                border-radius: 4px;
            }
            QListWidget::item:selected {
                background-color: #E3F2FD;
                color: #1565C0;
            }
            QListWidget::item:hover {
                background-color: #F5F5F5;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                min-width: 100px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #388E3C;
            }
            QPushButton:pressed {
                background-color: #2E7D32;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
            }
        """)

    def initUI(self):
        self.setWindowTitle('Recycle Bin')
        self.setMinimumWidth(300)
        self.setMinimumHeight(400)
        
        mainLayout = QVBoxLayout()
        mainLayout.setSpacing(10)
        mainLayout.setContentsMargins(15, 15, 15, 15)

        # Add header
        header = QLabel('Deleted Accounts', self)
        header.setStyleSheet('font-size: 16px; font-weight: bold; color: #1565C0; padding: 5px 0;')
        mainLayout.addWidget(header)

        # Add description
        description = QLabel('Select an account to restore:', self)
        description.setStyleSheet('color: #757575; margin-bottom: 5px;')
        mainLayout.addWidget(description)

        self.recycle_bin_list = QListWidget(self)
        self.updateRecycleBinList()
        mainLayout.addWidget(self.recycle_bin_list)

        buttonLayout = QHBoxLayout()
        buttonLayout.addStretch()
        
        self.restore_button = QPushButton('🔄 Restore Account', self)
        self.restore_button.clicked.connect(self.restoreAccount)
        self.restore_button.setEnabled(False)
        buttonLayout.addWidget(self.restore_button)

        mainLayout.addLayout(buttonLayout)
        self.setLayout(mainLayout)

        # Enable restore button only when an item is selected
        self.recycle_bin_list.itemSelectionChanged.connect(self.updateRestoreButton)

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

    def updateRestoreButton(self):
        self.restore_button.setEnabled(bool(self.recycle_bin_list.currentItem()))

class AuthipyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.accounts = []  
        self.recycle_bin = {}
        self.initUI()
        self.loadAccounts()  
        self.loadRecycleBin()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.updateCodes)
        self.timer.start(1000)

    def setStyle(self):
        self.setStyleSheet('''
            QWidget {
                font-family: 'Segoe UI', Arial;
                font-size: 14px;
                background-color: #f5f5f5;
            }
            QPushButton {
                background-color: #0078D4;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #005A9E;
            }
            QPushButton:pressed {
                background-color: #004578;
            }
            QLineEdit {
                padding: 8px;
                border: 1px solid #BDBDBD;
                border-radius: 4px;
                background-color: white;
            }
            QLineEdit:focus {
                border: 2px solid #0078D4;
            }
            QListWidget {
                border: 1px solid #BDBDBD;
                border-radius: 4px;
                background-color: white;
                padding: 5px;
            }
            QListWidget::item {
                padding: 8px;
                border-radius: 4px;
            }
            QListWidget::item:selected {
                background-color: #E3F2FD;
                color: #0078D4;
            }
            QListWidget::item:hover {
                background-color: #F5F5F5;
            }
            QLabel {
                color: #424242;
            }
            QMenuBar {
                background-color: #f5f5f5;
                border-bottom: 1px solid #BDBDBD;
            }
            QMenuBar::item {
                padding: 8px 15px;
            }
            QMenuBar::item:selected {
                background-color: #E3F2FD;
            }
            QMenu {
                background-color: white;
                border: 1px solid #BDBDBD;
            }
            QMenu::item {
                padding: 8px 20px;
            }
            QMenu::item:selected {
                background-color: #E3F2FD;
                color: #0078D4;
            }
        ''')
        
        # Enhanced fonts and sizing for important elements
        self.code_display.setStyleSheet("""
            QLabel {
                font-family: 'Consolas', 'Courier New';
                font-size: 24px;
                font-weight: bold;
                color: #1565C0;
                background-color: #E3F2FD;
                padding: 10px 20px;
                border-radius: 4px;
                border: 1px solid #BBDEFB;
            }
        """)
        
        self.code_label.setFont(QFont("Segoe UI", 16))
        self.timer_label.setFont(QFont("Segoe UI", 12))
        self.timer_label.setStyleSheet("color: #757575;")
        
        # Style the specific buttons
        self.show_qr_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #388E3C;
            }
            QPushButton:pressed {
                background-color: #2E7D32;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
            }
        """)

        self.add_button.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #0D47A1;
            }
        """)

    def initUI(self):
        self.setWindowTitle('Authipy')
        self.resize(400, 600)  # Slightly larger window

        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)

        mainLayout = QVBoxLayout()
        mainLayout.setSpacing(10)
        mainLayout.setContentsMargins(15, 15, 15, 15)

        # Group the input fields
        inputGroup = QVBoxLayout()
        inputGroup.setSpacing(8)

        self.website_input = QLineEdit(self)
        self.website_input.setPlaceholderText('✍ Enter Account Name')
        inputGroup.addWidget(self.website_input)

        self.issuer_input = QLineEdit(self)
        self.issuer_input.setPlaceholderText('🏢 Enter Issuer Name (Optional)')
        inputGroup.addWidget(self.issuer_input)

        self.secret_input = QLineEdit(self)
        self.secret_input.setPlaceholderText('🔑 Enter Secret Key')
        inputGroup.addWidget(self.secret_input)

        addButtonLayout = QHBoxLayout()
        addButtonLayout.addStretch()
        self.add_button = QPushButton('Add Account', self)
        self.add_button.setMinimumWidth(120)
        self.add_button.clicked.connect(self.addAccount)
        addButtonLayout.addWidget(self.add_button)

        inputGroup.addLayout(addButtonLayout)
        mainLayout.addLayout(inputGroup)

        # Accounts list with header
        listHeader = QLabel('Your Accounts', self)
        listHeader.setStyleSheet('font-size: 16px; font-weight: bold; color: #1565C0; padding: 5px 0;')
        mainLayout.addWidget(listHeader)

        self.accounts_list = QListWidget(self)
        self.accounts_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.accounts_list.customContextMenuRequested.connect(self.showContextMenu)
        self.accounts_list.itemClicked.connect(self.onAccountSelected)
        self.accounts_list.setMinimumHeight(200)
        mainLayout.addWidget(self.accounts_list)

        # Code display section
        codeGroup = QVBoxLayout()
        codeGroup.setSpacing(5)

        codeHeader = QHBoxLayout()
        self.code_label = QLabel('Current Code:', self)
        codeHeader.addWidget(self.code_label)
        self.timer_label = QLabel('Time left: --', self)
        self.timer_label.setAlignment(Qt.AlignRight)
        codeHeader.addWidget(self.timer_label)
        codeGroup.addLayout(codeHeader)

        self.code_display = QLabel('------', self)
        self.code_display.setAlignment(Qt.AlignCenter)
        self.code_display.setCursor(QCursor(Qt.PointingHandCursor))
        self.code_display.mousePressEvent = self.copyToClipboard
        codeGroup.addWidget(self.code_display)

        mainLayout.addLayout(codeGroup)

        # QR code section
        self.qr_label = QLabel(self)
        self.qr_label.setAlignment(Qt.AlignCenter)
        mainLayout.addWidget(self.qr_label)

        self.show_qr_button = QPushButton('Show QR Code', self)
        self.show_qr_button.clicked.connect(self.toggleQRCode)
        self.show_qr_button.setEnabled(False)
        mainLayout.addWidget(self.show_qr_button)

        self.main_widget.setLayout(mainLayout)
        
        # Menu bar
        menubar = self.menuBar()
        task_menu = menubar.addMenu('Options')

        recycle_bin_action = QAction('🗑️ Recycle Bin', self)
        recycle_bin_action.triggered.connect(self.openRecycleBin)
        task_menu.addAction(recycle_bin_action)

        export_action = QAction('📤 Export Accounts', self)
        export_action.triggered.connect(self.exportAccounts)
        task_menu.addAction(export_action)

        import_action = QAction('📥 Import Accounts', self)
        import_action.triggered.connect(self.importAccounts)
        task_menu.addAction(import_action)

        help_action = QAction('❓ Help', self)
        help_action.triggered.connect(self.openHelp)
        menubar.addAction(help_action)

        about_action = QAction('ℹ️ About', self)
        about_action.triggered.connect(self.openAbout)
        menubar.addAction(about_action)

        # Remove Profile action from options
        # task_menu.removeAction(profile_action)

        self.setMenuBar(menubar)

        self.setStyle()

    def addAccount(self):
        website = self.website_input.text().strip()
        secret = self.secret_input.text().strip()
        issuer = self.issuer_input.text().strip() or None  

        if not website or not secret:
            QMessageBox.warning(self, 'Input Error', 'Both website and secret code are required.')
            return

        if any(account['name'] == website for account in self.accounts):
            QMessageBox.warning(self, 'Duplicate Account', 'This website already exists.')
            return

        account_data = {
            "name": website,
            "secret": secret,
            "issuer": issuer,  # Remove capitalize() to preserve case
            "type": "totp",
            "counter": None,
            "url": f"otpauth://totp/{website}?secret={secret}{('&issuer=' + issuer) if issuer else ''}"
        }
        self.accounts.append(account_data)  
        self.updateAccountList()
        self.website_input.clear()
        self.secret_input.clear()
        self.issuer_input.clear()
        self.saveAccounts()
        QMessageBox.information(self, 'Success', 'Account added successfully.')

    def updateAccountList(self):
        self.accounts_list.clear()
        for account in self.accounts:
            item = QListWidgetItem(account['name'])
            item.setIcon(QIcon('path/to/icon.png'))  # Placeholder icon path
            self.accounts_list.addItem(item)

    def onAccountSelected(self, item):
        self.show_qr_button.setEnabled(True)
        self.qr_label.clear()
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
            account = next(acc for acc in self.accounts if acc['name'] == website)  
            secret = account['secret']
            totp = pyotp.TOTP(secret)
            url = totp.provisioning_uri(name=website, issuer_name=account['issuer'] or '')
            qr = pyqrcode.create(url)
            qr_filename = f'{website}_qrcode.png'
            try:
                qr.png(qr_filename, scale=4)
                pixmap = QPixmap(qr_filename)
                self.qr_label.setPixmap(pixmap)
                os.remove(qr_filename)
            except Exception as e:
                QMessageBox.critical(self, 'QR Code Error', f'Failed to generate QR code: {e}')

    def updateCodes(self):
        current_item = self.accounts_list.currentItem()
        if current_item:
            try:
                website = current_item.text()
                account = next(acc for acc in self.accounts if acc['name'] == website)  
                secret = account['secret']
                totp = pyotp.TOTP(secret)
                self.updateCode(totp)
            except Exception as e:
                self.code_display.setText("Invalid")
                self.timer_label.setText("Error")

    def updateCode(self, totp):
        code = totp.now()
        self.code_display.setText(code)
        
        remaining_time = 30 - int(time.time()) % 30
        self.timer_label.setText(f'Time left: {remaining_time} seconds')

    def copyToClipboard(self, event):
        pyperclip.copy(self.code_display.text())
       

    def showContextMenu(self, pos):
        menu = QMenu(self.accounts_list)
        delete_action = menu.addAction("Delete Account")
        action = menu.exec_(self.accounts_list.mapToGlobal(pos))
        if action == delete_action:
            self.deleteAccount()

    def deleteAccount(self):
        current_item = self.accounts_list.currentItem()
        if current_item:
            website = current_item.text()
            reply = QMessageBox.question(self, 'Delete Account', f"Are you sure you want to delete the account for {website}?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.recycle_bin[website] = self.accounts.pop(self.accounts_list.row(current_item))
                self.updateAccountList()
                self.saveAccounts()
                self.saveRecycleBin()

    def loadAccounts(self):
        if os.path.exists(ACCOUNTS_FILE):
            try:
                with open(ACCOUNTS_FILE, 'r') as f:
                    self.accounts = json.load(f)
                    if not isinstance(self.accounts, list):
                        raise ValueError("Invalid format: accounts must be a list.")
                self.updateAccountList()
            except (json.JSONDecodeError, ValueError) as e:
                QMessageBox.critical(self, 'Load Error', f'Error loading accounts: {e}')
                self.accounts = []  
        else:
            self.accounts = []

    def saveAccounts(self):
        try:
            with open(ACCOUNTS_FILE, 'w') as f:
                json.dump(self.accounts, f, indent=4)
        except Exception as e:
            QMessageBox.critical(self, 'Save Error', f'Error saving accounts: {e}')

    def loadRecycleBin(self):
        if os.path.exists(RECYCLE_BIN_FILE):
            try:
                with open(RECYCLE_BIN_FILE, 'r') as f:
                    self.recycle_bin = json.load(f)
            except json.JSONDecodeError:
                self.recycle_bin = {}
        else:
            self.recycle_bin = {}

    def saveRecycleBin(self):
        try:
            with open(RECYCLE_BIN_FILE, 'w') as f:
                json.dump(self.recycle_bin, f, indent=4)
        except Exception as e:
            QMessageBox.critical(self, 'Save Error', f'Error saving recycle bin: {e}')

    def openRecycleBin(self):
        self.recycle_bin_window = RecycleBinWindow(self.recycle_bin, self.restoreAccount)
        self.recycle_bin_window.show()

    def restoreAccount(self, website):
        if website in self.recycle_bin:
            self.accounts.append(self.recycle_bin.pop(website))
            self.updateAccountList()
            self.saveAccounts()
            self.saveRecycleBin()
            QMessageBox.information(self, 'Restore Account', f'Account for {website} restored successfully.')

    def exportAccounts(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Export Accounts", "", "JSON Files (*.json)")
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.accounts, f, indent=4)
                QMessageBox.information(self, 'Export Success', 'Accounts exported successfully.')
            except Exception as e:
                QMessageBox.critical(self, 'Export Error', f'Failed to export accounts: {e}')

    def importAccounts(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Import Accounts", "", "JSON Files (*.json)")
        if filename:
            try:
                with open(filename, 'r') as f:
                    imported_accounts = json.load(f)
                    if isinstance(imported_accounts, list):
                        self.accounts.extend(imported_accounts)
                        self.updateAccountList()
                        self.saveAccounts()
                        QMessageBox.information(self, 'Import Success', 'Accounts imported successfully.')
                    else:
                        raise ValueError("Invalid file format: Expected a list of accounts.")
            except (json.JSONDecodeError, ValueError) as e:
                QMessageBox.critical(self, 'Import Error', f'Error importing accounts: {e}')


    def openHelp(self):
        QMessageBox.information(self, 'Help', 'Help section is under construction.')

    def openAbout(self):
        QMessageBox.information(self, 'About', 'Authipy version 1.0.0\nDeveloped by TanmoyTheBoT.')

def main():
    app = QApplication(sys.argv)
    authipy_app = AuthipyApp()
    authipy_app.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
