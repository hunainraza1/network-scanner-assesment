@echo off
echo ================================
echo  Network Scanner Installation
echo ================================
echo.

python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Python is not installed or not in PATH.
    echo Please install Python 3.11+ from:
    echo https://www.python.org/downloads/
    pause
    exit /b
)

echo Python detected.
echo No external dependencies required.
echo Installation complete.

echo to run:
	echo Right click on the folder with all the dependencies "Assesment" 
	echo click "open in terminal" 
	echo type "python scanner.py 192.168.0.0/24 --json --report"

pause