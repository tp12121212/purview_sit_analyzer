#!/bin/bash
# setup_purview_project.sh

set -e

echo "
=== Purview SIT Analyzer Setup for macOS ===
"

# ---- Check for Homebrew ----
if ! command -v brew &> /dev/null; then
    echo "Homebrew not found. Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else
    echo "Homebrew is already installed."
fi

# ---- Check for Python 3.11 ----
if ! python3 --version | grep -q "3.11"; then
    echo "Installing Python 3.11 via Homebrew..."
    brew install python@3.11
else
    echo "Python 3.11 is already installed."
fi

# ---- Install system dependencies ----
echo "Installing Tesseract OCR and Poppler..."
brew install tesseract poppler

# ---- Create virtual environment ----
echo "Creating virtual environment 'purview_env'..."
python3 -m venv purview_env

# ---- Activate virtual environment ----
echo "Activating virtual environment..."
source purview_env/bin/activate

# ---- Upgrade pip ----
echo "Upgrading pip..."
pip install --upgrade pip

# ---- Install Python dependencies ----
echo "Installing Python dependencies..."
pip install   python-docx==0.8.11   openpyxl==3.1.2   python-pptx==0.6.21   pdfplumber==0.10.3   pdf2image==1.16.3   pytesseract==0.3.10   pandas==2.2.3   requests==2.32.3

# ---- Freeze requirements ----
echo "Generating requirements.txt..."
pip freeze > requirements.txt

echo "
=== Setup Complete ==="
echo "To activate the environment, run: source purview_env/bin/activate"
echo "To run the analyzer: python purview_sit_analyzer.py --input_folder ./input --output_folder ./output --min_keyword_length 4 --min_phrase_words 2 --max_phrase_words 4"
