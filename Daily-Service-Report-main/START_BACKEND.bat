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
set VENV_ACTIVATED=0
if exist "venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
    set VENV_ACTIVATED=1
) else if exist ".venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
    set VENV_ACTIVATED=1
) else if exist "env\Scripts\activate.bat" (
    echo Activating virtual environment...
    call env\Scripts\activate.bat
    set VENV_ACTIVATED=1
) else (
    echo No virtual environment found. Using system Python.
    echo Consider creating a virtual environment: python -m venv venv
    echo.
)

REM Check if requirements are installed (check in the active Python environment)
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
) else (
    REM Verify critical dependencies are available in the active environment
    python -c "import flask_limiter" >nul 2>&1
    if errorlevel 1 (
        echo Installing missing dependencies in active environment...
        pip install -r requirements.txt
        echo.
    )
)

REM Check if .env file exists
if not exist ".env" (
    echo WARNING: .env file not found. Using default settings.
    echo Copy env.example to .env and configure it if needed.
    echo.
)

echo Starting Flask backend server...
echo.

REM Check if port 5000 is already in use and handle automatically
netstat -ano | findstr :5000 >nul 2>&1
if %errorlevel% == 0 (
    echo Port 5000 is in use. Attempting to free it automatically...
    echo.
    
    REM Try to automatically kill processes on port 5000
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5000 ^| findstr LISTENING') do (
        echo Killing process ID: %%a on port 5000...
        taskkill /PID %%a /F >nul 2>&1
        if not errorlevel 1 (
            echo   Successfully killed process %%a
        ) else (
            echo   Could not kill process %%a (may require admin rights)
        )
    )
    
    echo.
    echo Waiting 2 seconds for port to be released...
    timeout /t 2 /nobreak >nul 2>&1
    
    REM Check again if port 5000 is free
    netstat -ano | findstr :5000 >nul 2>&1
    if %errorlevel% == 0 (
        echo Port 5000 is still in use. Automatically using port 5001 instead...
        set FLASK_PORT=5001
        echo.
    ) else (
        echo Port 5000 is now free. Using port 5000...
        echo.
    )
) else (
    echo Port 5000 is available. Using port 5000...
    echo.
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

