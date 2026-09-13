@echo off
rem Aragami CLI, pinned to the tor target.
rem ARAGAMI_TARGET only sets a default; an explicit --target still wins.
setlocal
set "ARAGAMI_TARGET=tor"
node "%~dp0..\cli\index.mjs" %*
exit /b %ERRORLEVEL%