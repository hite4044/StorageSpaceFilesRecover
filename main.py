"""GUI 入口（管理员运行）:  .venv\\Scripts\\python.exe main.py"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from ssrecover.rawdisk import is_admin  # noqa: E402

if not is_admin():
    print("!! 请以管理员身份运行（需要直读物理硬盘）")
    print("   例如: 右键 PowerShell → 以管理员身份运行 → "
          f"{ROOT}\\venv\\Scripts\\python.exe {ROOT}\\main.py")
    sys.exit(1)

from PySide6.QtWidgets import QApplication  # noqa: E402

from gui.mainwindow import MainWindow  # noqa: E402


def main() -> int:
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
