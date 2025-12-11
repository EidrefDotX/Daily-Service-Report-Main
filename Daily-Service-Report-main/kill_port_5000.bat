@echo off
echo ========================================
echo Killing processes using port 5000
echo ========================================
echo.

REM Find and kill processes using port 5000
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5000 ^| findstr LISTENING') do (
    echo Killing process ID: %%a
    taskkill /PID %%a /F >nul 2>&1
    if errorlevel 1 (
        echo   Failed to kill process %%a (may require admin rights)
    ) else (
        echo   Successfully killed process %%a
    )
)

echo.
echo Done! You can now start the backend server.
echo.
pause

