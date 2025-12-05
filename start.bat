@echo off
REM Start the DashScope chat server
setlocal
if not exist node_modules (
  echo Installing dependencies...
  npm install
)
echo Starting server on port %PORT% (default 3021)...
npm start
endlocal
