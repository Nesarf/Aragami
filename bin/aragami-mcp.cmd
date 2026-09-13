@echo off
rem Aragami MCP stdio server launcher (portable, no-install distribution).
rem Point an MCP client at this file; stdout carries the protocol, so nothing
rem may be echoed here. Requires Node.js >= 18 on PATH.
setlocal
node "%~dp0..\mcp\index.mjs" %*
exit /b %ERRORLEVEL%