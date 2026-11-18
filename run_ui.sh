#!/usr/bin/env bash
# Start the live-demo web UI (macOS / Linux).
#   ./run_ui.sh
# First run: creates .venv and installs requirements.txt. Later runs start immediately.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
if [ ! -x ".venv/bin/python" ]; then
    echo "Creating virtual environment in .venv ..."
    "$PYTHON" -m venv .venv
    .venv/bin/python -m pip install --upgrade pip
    .venv/bin/python -m pip install -r requirements.txt
elif ! .venv/bin/python -c "import streamlit, pandas, cryptography" 2>/dev/null; then
    echo "Installing requirements ..."
    .venv/bin/python -m pip install -r requirements.txt
fi

exec .venv/bin/python -m streamlit run ui/app.py "$@"
