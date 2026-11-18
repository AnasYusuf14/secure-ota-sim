@echo off
REM Start the live-demo web UI (Windows).
REM   run_ui.bat
REM First run: creates .venv and installs requirements.txt. Later runs start immediately.
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment in .venv ...
    py -3 -m venv .venv 2>nul || python -m venv .venv
    if errorlevel 1 (
        echo Could not create the virtual environment. Is Python 3.10+ installed?
        exit /b 1
    )
    ".venv\Scripts\python.exe" -m pip install --upgrade pip
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
) else (
    ".venv\Scripts\python.exe" -c "import streamlit, pandas, cryptography" 2>nul || ".venv\Scripts\python.exe" -m pip install -r requirements.txt
)

".venv\Scripts\python.exe" -m streamlit run ui\app.py %*
