import os
import json
import pytest
import tempfile
import shutil
from PyQt5.QtWidgets import QApplication, QMessageBox, QMenu
from PyQt5.QtCore import Qt
from PyQt5.QtTest import QTest
from PyQt5.QtGui import QMouseEvent
from authipy.main import AuthipyApp, RecycleBinWindow

# Patch QMessageBox to always return Yes/Ok
@pytest.fixture(autouse=True)
def mock_message_boxes(monkeypatch):
    monkeypatch.setattr(QMessageBox, 'question', lambda *args: QMessageBox.Yes)
    monkeypatch.setattr(QMessageBox, 'warning', lambda *args: QMessageBox.Ok)
    monkeypatch.setattr(QMessageBox, 'information', lambda *args: QMessageBox.Ok)
    monkeypatch.setattr(QMessageBox, 'critical', lambda *args: QMessageBox.Ok)

# Required for Qt Tests
@pytest.fixture(scope="session")
def qapp():
    app = QApplication([])
    yield app
    app.quit()

@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path

@pytest.fixture
def app(qapp, monkeypatch, temp_dir):
    # Set up a temporary config directory for testing
    test_config_dir = temp_dir / ".config" / "authipy"
    test_config_dir.mkdir(parents=True)
    
    # Patch the CONFIG_DIR to use temporary directory
    monkeypatch.setattr('authipy.main.CONFIG_DIR', str(test_config_dir))
    monkeypatch.setattr('authipy.main.ACCOUNTS_FILE', str(test_config_dir / 'accounts.json'))
    monkeypatch.setattr('authipy.main.RECYCLE_BIN_FILE', str(test_config_dir / 'recycle_bin.json'))
    
    # Create application instance
    app = AuthipyApp()
    yield app
    
    # Cleanup
    shutil.rmtree(str(test_config_dir))

@pytest.fixture
def app_with_account(app):
    app.website_input.setText("TestSite")
    app.secret_input.setText("JBSWY3DPEHPK3PXP")
    app.issuer_input.setText("TestIssuer")
    QTest.mouseClick(app.add_button, Qt.LeftButton)
    return app

def test_initial_state(app):
    """Test initial state of application"""
    assert len(app.accounts) == 0
    assert len(app.recycle_bin) == 0
    assert app.website_input.text() == ""
    assert app.secret_input.text() == ""
    assert app.issuer_input.text() == ""
    assert app.show_qr_button.isEnabled() == False

@pytest.mark.parametrize("website,secret,issuer", [
    ("GitHub", "JBSWY3DPEHPK3PXP", "GitHub2FA"),
    ("TestSite", "JBSWY3DPEHPK3PXP", "TestIssuer"),
    ("Gmail", "JBSWY3DPEHPK3PXP", None)
])
def test_add_account(app, website, secret, issuer):
    """Test adding accounts with different parameters"""
    app.website_input.setText(website)
    app.secret_input.setText(secret)
    if issuer:
        app.issuer_input.setText(issuer)
    QTest.mouseClick(app.add_button, Qt.LeftButton)
    
    assert len(app.accounts) == 1
    account = app.accounts[0]
    assert account["name"] == website
    assert account["secret"] == secret
    assert account["issuer"] == issuer
    assert app.website_input.text() == ""
    assert app.secret_input.text() == ""
    assert app.issuer_input.text() == ""

def test_delete_account(app_with_account):
    """Test deleting an account"""
    assert len(app_with_account.accounts) == 1
    app_with_account.accounts_list.setCurrentRow(0)
    app_with_account.deleteAccount()
    
    assert len(app_with_account.accounts) == 0
    assert len(app_with_account.recycle_bin) == 1
    assert "TestSite" in app_with_account.recycle_bin

def test_restore_account(app_with_account):
    """Test restoring an account from recycle bin"""
    app_with_account.accounts_list.setCurrentRow(0)
    app_with_account.deleteAccount()
    assert len(app_with_account.accounts) == 0
    
    website = next(iter(app_with_account.recycle_bin.keys()))
    app_with_account.restoreAccount(website)
    
    assert len(app_with_account.accounts) == 1
    assert len(app_with_account.recycle_bin) == 0
    assert app_with_account.accounts[0]["name"] == "TestSite"

def test_invalid_account_add(app):
    """Test adding account with invalid input"""
    # Empty fields
    QTest.mouseClick(app.add_button, Qt.LeftButton)
    assert len(app.accounts) == 0

    # Missing secret
    app.website_input.setText("TestSite")
    QTest.mouseClick(app.add_button, Qt.LeftButton)
    assert len(app.accounts) == 0

    # Missing website
    app.website_input.setText("")
    app.secret_input.setText("JBSWY3DPEHPK3PXP")
    QTest.mouseClick(app.add_button, Qt.LeftButton)
    assert len(app.accounts) == 0

def test_duplicate_account(app):
    """Test adding duplicate account"""
    # Add first account
    app.website_input.setText("TestSite")
    app.secret_input.setText("JBSWY3DPEHPK3PXP")
    QTest.mouseClick(app.add_button, Qt.LeftButton)
    
    # Try to add duplicate
    app.website_input.setText("TestSite")
    app.secret_input.setText("DIFFERENTKEY123")
    QTest.mouseClick(app.add_button, Qt.LeftButton)
    
    assert len(app.accounts) == 1
    assert app.accounts[0]["secret"] == "JBSWY3DPEHPK3PXP"

def test_qr_code_toggle(app_with_account, temp_dir):
    """Test QR code toggle functionality"""
    os.chdir(str(temp_dir))
    
    # Properly trigger item selection
    app_with_account.accounts_list.setCurrentRow(0)
    app_with_account.onAccountSelected(app_with_account.accounts_list.currentItem())
    assert app_with_account.show_qr_button.isEnabled()
    
    # Show QR code
    QTest.mouseClick(app_with_account.show_qr_button, Qt.LeftButton)
    assert app_with_account.qr_label.pixmap() is not None
    assert app_with_account.show_qr_button.text() == "Hide QR Code"
    
    # Hide QR code
    QTest.mouseClick(app_with_account.show_qr_button, Qt.LeftButton)
    assert app_with_account.qr_label.pixmap() is None
    assert app_with_account.show_qr_button.text() == "Show QR Code"

def test_code_generation_and_timer(app_with_account):
    """Test TOTP code generation and timer"""
    app_with_account.accounts_list.setCurrentRow(0)
    
    # Initial code generation
    app_with_account.updateCodes()
    assert app_with_account.code_display.text() != "------"
    assert app_with_account.code_display.text() != "Invalid"
    assert "Time left:" in app_with_account.timer_label.text()
    
    # Test code copy
    initial_code = app_with_account.code_display.text()
    event = QMouseEvent(QMouseEvent.MouseButtonPress, app_with_account.code_display.pos(), 
                       Qt.LeftButton, Qt.LeftButton, Qt.NoModifier)
    app_with_account.copyToClipboard(event)
    import pyperclip
    assert pyperclip.paste() == initial_code

def test_file_operations(app_with_account, temp_dir):
    """Test file saving and loading operations"""
    # Test accounts file creation
    accounts_file = os.path.join(str(temp_dir), ".config", "authipy", "accounts.json")
    assert os.path.exists(accounts_file)
    
    # Test export
    export_file = os.path.join(str(temp_dir), "export.json")
    with open(export_file, 'w') as f:
        json.dump(app_with_account.accounts, f)
    
    # Clear and test import
    app_with_account.accounts = []
    app_with_account.updateAccountList()
    with open(export_file, 'r') as f:
        imported_accounts = json.load(f)
        app_with_account.accounts.extend(imported_accounts)
        app_with_account.updateAccountList()
    
    assert len(app_with_account.accounts) == 1
    assert app_with_account.accounts[0]["name"] == "TestSite"

def test_recycle_bin_window(app_with_account):
    """Test recycle bin window functionality"""
    # Delete an account first
    app_with_account.accounts_list.setCurrentRow(0)
    app_with_account.deleteAccount()
    
    # Open recycle bin
    app_with_account.openRecycleBin()
    assert hasattr(app_with_account, 'recycle_bin_window')
    assert isinstance(app_with_account.recycle_bin_window, RecycleBinWindow)
    
    # Test restore button state
    assert not app_with_account.recycle_bin_window.restore_button.isEnabled()
    app_with_account.recycle_bin_window.recycle_bin_list.setCurrentRow(0)
    assert app_with_account.recycle_bin_window.restore_button.isEnabled()

def test_menu_actions(app):
    """Test menu actions"""
    # Test Help menu
    help_action = next(action for action in app.menuBar().actions() 
                      if action.text() == '❓ Help')
    help_action.trigger()
    
    # Test About menu
    about_action = next(action for action in app.menuBar().actions() 
                       if action.text() == 'ℹ️ About')
    about_action.trigger()

def test_context_menu(app_with_account):
    """Test context menu functionality"""
    app_with_account.accounts_list.setCurrentRow(0)
    
    # Simulate delete through deleteAccount directly since we can't trigger QMenu in test
    app_with_account.deleteAccount()
    
    assert len(app_with_account.accounts) == 0
    assert len(app_with_account.recycle_bin) == 1
    assert "TestSite" in app_with_account.recycle_bin

def test_cleanup(app_with_account, temp_dir):
    """Test cleanup and file removal"""
    config_dir = os.path.join(str(temp_dir), ".config", "authipy")
    assert os.path.exists(config_dir)
    
    # Cleanup happens in fixture
    del app_with_account
    # Directory should still exist until fixture cleanup
    assert os.path.exists(config_dir)