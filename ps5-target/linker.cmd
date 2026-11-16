@echo off
setlocal
where python >nul 2>nul
if %ERRORLEVEL%==0 (
    python "%~dp0linker.py" %*
) else (
    py -3 "%~dp0linker.py" %*
)
exit /b %ERRORLEVEL%
