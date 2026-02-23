@echo off
echo ==========================================
echo   Installing Network Scanner Dependencies
echo ==========================================
pip install -r requirements.txt
echo.
echo Installation Complete! 
echo.
echo To run a scan, use the following command:
echo python scanner.py 192.168.0.0/24 --json --report
echo.
pause