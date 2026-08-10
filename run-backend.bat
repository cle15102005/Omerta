@echo off
cd /d "%~dp0backend"
if not exist node_modules (
    echo Installing backend dependencies...
    npm install
)
echo Starting backend dev server...
npm run dev