#!/usr/bin/env bash

set -e

echo "🔧 Creating virtual environment: lexicon_env"

python3.11 -m venv lexicon_env

echo "📦 Activating environment"
# shellcheck disable=SC1091
source lexicon_env/bin/activate

echo "⬆️ Upgrading pip"
pip install --upgrade pip

echo "📚 Installing dependencies"
pip install \
    python-docx \
    pdfplumber \
    pandas \
    openpyxl \
    argparse \
    wordfreq

echo "✨ Setup complete!"
echo "To activate the environment later, run:"
echo "source lexicon_env/bin/activate"
