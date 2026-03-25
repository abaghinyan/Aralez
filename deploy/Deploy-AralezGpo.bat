@echo off
:: ============================================================================
:: Aralez GPO Startup Script
:: Deploy and execute Aralez during machine boot (runs as SYSTEM)
:: ============================================================================
:: Configure your network share where aralez_x64_windows.exe is hosted
set DEPLOY_SHARE=\\domain.local\NETLOGON\AralezDeploy

:: Configure where the results should be uploaded
set OUTPUT_DEST=\\domain.local\ForensicEvidence$\Incoming

:: Local working directory
set WORK_DIR=C:\Windows\Temp\AralezGPO

:: Log file for troubleshooting GPO execution
set LOG_FILE=C:\Windows\Temp\Aralez_GPO.log

echo %DATE% %TIME% - Starting Aralez GPO deployment > "%LOG_FILE%"

:: Check if already run today (Optional - to prevent running every reboot)
:: if exist "C:\Windows\Temp\aralez_run_today.flag" exit /b 0

:: Create local workspace
mkdir "%WORK_DIR%" 2>nul
cd /d "%WORK_DIR%"

echo %DATE% %TIME% - Copying binaries from %DEPLOY_SHARE% >> "%LOG_FILE%"
copy /Y "%DEPLOY_SHARE%\aralez_x64_windows.exe" "%WORK_DIR%\aralez.exe" >> "%LOG_FILE%" 2>&1

:: Verify copy was successful
if not exist "%WORK_DIR%\aralez.exe" (
    echo %DATE% %TIME% - ERROR: Failed to copy aralez.exe from share >> "%LOG_FILE%"
    exit /b 1
)

echo %DATE% %TIME% - Executing Aralez Collection >> "%LOG_FILE%"
"%WORK_DIR%\aralez.exe" --output "%OUTPUT_DEST%" >> "%LOG_FILE%" 2>&1
set ARALEZ_EXIT=%ERRORLEVEL%

echo %DATE% %TIME% - Aralez finished with exit code %ARALEZ_EXIT% >> "%LOG_FILE%"

:: Cleanup
cd \
rmdir /S /Q "%WORK_DIR%"

:: Touch flag file so we don't run constantly (optional)
:: echo %DATE% > "C:\Windows\Temp\aralez_run_today.flag"

exit /b %ARALEZ_EXIT%
