@echo off
rem Aragami CLI launcher (portable, no-install distribution).
rem Requires Node.js >= 18 on PATH. Forwards all arguments and the exit code.
setlocal
node "%~dp0..\cli\index.mjs" %*
exit /b %ERRORLEVEL%