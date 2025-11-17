@echo off
cd /d "%~dp0"
echo Starting Daily Service Report Backend...
echo.
echo Creating default engineer users (EN001-EN009)
echo Password: #DotXsolutions.opc
echo.
echo Finding your IP address...
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4 Address"') do (
  set IP=%%a
  goto :found
)
:found
echo.
echo Server will be available at:
echo   - On this computer: http://127.0.0.1:5000
echo   - On your phone/network: http://%IP:~1%:5000
echo.
set RUN_MODE=%1
if "%RUN_MODE%"=="prod" (
  echo Starting in production mode with Waitress...
  set FLASK_DEBUG=false
  py -m waitress --listen=0.0.0.0:5000 app:create_app
) else (
  python app.py
)
pause

 