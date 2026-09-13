@echo off
rem Aragami MCP stdio server, pinned to the tor target.
rem stdout carries the protocol, so nothing may be echoed here.
setlocal
set "ARAGAMI_TARGET=tor"
node "%~dp0..\mcp\index.mjs" %*
exit /b %ERRORLEVEL%