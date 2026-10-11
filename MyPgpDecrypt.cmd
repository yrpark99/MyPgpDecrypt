@echo off
start /wait "%~dp0MyPgpDecrypt.exe" %*
exit /b %ERRORLEVEL%
