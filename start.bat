@echo off
cd /d "%~dp0"

echo Starting database...
docker-compose up -d

start "Backend" cmd /k "%~dp0run-backend.bat"
start "Frontend" cmd /k "%~dp0run-frontend.bat"