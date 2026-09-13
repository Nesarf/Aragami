@echo off
rem Aragami MCP stdio server, pinned to the firefox target.
rem stdout carries the protocol, so nothing may be echoed here.
setlocal
set "ARAGAMI_TARGET=firefox"
node "%~dp0..\mcp\index.mjs" %*
exit /b %ERRORLEVEL%