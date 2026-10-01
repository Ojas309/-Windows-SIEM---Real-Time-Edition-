@echo off
echo ==========================================
echo    Windows SIEM - Desktop Edition
echo ==========================================
echo.

cd /d "%~dp0"

echo Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found! Please install Python from python.org
    pause
    exit /b 1
)

echo Starting SIEM...
echo.
echo Dashboard will open at: http://localhost:5000
echo.
echo DO NOT CLOSE THIS WINDOW while using SIEM
echo.

python siem_advanced.py

pause