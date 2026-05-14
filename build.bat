@echo off
echo Building WiFi Security Scanner...
py -m PyInstaller --noconfirm --onefile --windowed --name WiFiScanner app.py
echo Build complete! Executable is in the dist folder.
pause
