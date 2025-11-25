I	#!/bin/bash
# setup_purview_project.sh
set -e

echo "Setting up Purview SIT Analyzer environment..."
if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi
if ! python3 --version | grep -q "3.11"; then
    echo "Installing Python 3.11..."
    brew install python@3.11
fi
brew install tesseract poppler
python3 -m venv purview_env
source purview_env/bin/activate
pip install --upgrade pip
pip install python-docx==0.8.11 openpyxl==3.1.2 python-pptx==0.6.21 pdfplumber==0.10.3 pdf2image==1.16.3 pytesseract==0.3.10 pandas==2.2.3 requests==2.32.3
pip freeze > requirements.txt
echo "Setup complete. Activate with: source purview_env/bin/activate"
echo "Run analyzer: python purview_sit_analyzer.py --input_folder ./input --output_folder ./output"
