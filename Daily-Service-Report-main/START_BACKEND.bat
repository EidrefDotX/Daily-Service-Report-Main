@echo off
echo ========================================
echo Starting Daily Service Report Backend
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

echo Python found:
python --version
echo.

REM Check if virtual environment exists and activate it
if exist "venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
) else if exist ".venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
) else if exist "env\Scripts\activate.bat" (
    echo Activating virtual environment...
    call env\Scripts\activate.bat
) else (
    echo No virtual environment found. Using system Python.
    echo Consider creating a virtual environment: python -m venv venv
    echo.
)

REM Check if requirements are installed
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies from requirements.txt...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
    echo.
)

REM Check if .env file exists
if not exist ".env" (
    echo WARNING: .env file not found. Using default settings.
    echo Copy env.example to .env and configure it if needed.
    echo.
)

echo Starting Flask backend server...
echo.

REM Check if port 5000 is already in use
netstat -ano | findstr :5000 >nul 2>&1
if %errorlevel% == 0 (
    echo WARNING: Port 5000 appears to be in use!
    echo.
    echo Finding process using port 5000...
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5000 ^| findstr LISTENING') do (
        echo Process ID: %%a
        tasklist /FI "PID eq %%a" /FO TABLE
        echo.
        echo To kill this process, run:
        echo   taskkill /PID %%a /F
        echo.
    )
    echo.
    echo Options:
    echo   1. Run kill_port_5000.bat to automatically kill processes on port 5000
    echo   2. Use a different port by setting FLASK_PORT environment variable
    echo   3. Manually kill processes: taskkill /PID [PID] /F
    echo.
    set /p choice="Do you want to try using port 5001 instead? (Y/N): "
    if /i "!choice!"=="Y" (
        set FLASK_PORT=5001
        echo Using port 5001 instead...
    ) else (
        pause
        exit /b 1
    )
)

python app.py
if errorlevel 1 (
    echo.
    echo ERROR: Failed to start the server!
    echo.
    echo Common issues:
    echo - Port 5000 is already in use
    echo - Missing dependencies (run: pip install -r requirements.txt)
    echo - Database connection error
    echo.
    pause
    exit /b 1
)

pause

