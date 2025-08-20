# jasmin_gui_integration.py
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GUI_DIR = ROOT  # adjust if stored under a subfolder

# Import jasmin session env
sys.path.insert(0, str(ROOT.parent))
from jasmin import get_current_session_env

def gui_command_handler(_args=None) -> bool:
    try:
        from jasmin_gui_main import JasminGUI
        from PyQt6.QtWidgets import QApplication, QMessageBox
    except Exception as e:
        print(f"[!] GUI unavailable: {e}")
        print("    pip install PyQt6")
        return False

    env = get_current_session_env()
    if not env:
        print("[!] No active session. Use:")
        print("    jasmin> target <name> <ip>")
        return False

    app = QApplication.instance() or QApplication(sys.argv)
    w = JasminGUI(env)
    w.show()
    app.exec()
    return True
