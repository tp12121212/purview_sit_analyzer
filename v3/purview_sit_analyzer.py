
import os
import re
import json
import logging
import argparse
import requests
import pandas as pd
from collections import Counter
from pdf2image import convert_from_path
import pytesseract
import pdfplumber
from docx import Document
from pptx import Presentation
import openpyxl
from PIL import Image

# ---- Configure Logging ----
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ---- Load Stopwords from GitHub ----
STOPWORDS_URL = "https://raw.githubusercontent.com/tp12121212/purview_sit_analyzer/refs/heads/main/english.txt"
try:
    response = requests.get(STOPWORDS_URL)
    stop_words = set(response.text.split())
    logging.info(f"Loaded {len(stop_words)} stop words from GitHub.")
except Exception as e:
    logging.error(f"Failed to load stop words from GitHub: {e}")
    stop_words = set()

# ---- Argument Parser ----
parser = argparse.ArgumentParser(description="Purview SIT Analyzer")
parser.add_argument('--input_folder', required=True, help='Folder containing files to analyze')
parser.add_argument('--output_folder', required=True, help='Folder to save output CSV files')
parser.add_argument('--min_keyword_length', type=int, default=4, help='Minimum length of keyword')
parser.add_argument('--min_phrase_words', type=int, default=2, help='Minimum words in phrase')
parser.add_argument('--max_phrase_words', type=int, default=4, help='Maximum words in phrase')
args = parser.parse_args()

input_folder = args.input_folder
output_folder = args.output_folder
min_keyword_length = args.min_keyword_length
min_phrase_words = args.min_phrase_words
max_phrase_words = args.max_phrase_words

os.makedirs(output_folder, exist_ok=True)

# ---- Load Regex Patterns ----
with open('regex_patterns.json', 'r') as f:
    regex_patterns = json.load(f)

# ---- Helper Functions ----
def extract_text_from_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    text = ""
    try:
        if ext in ['.txt', '.csv']:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        elif ext == '.docx':
            doc = Document(filepath)
            text = "\n".join([p.text for p in doc.paragraphs])
        elif ext == '.xlsx':
            wb = openpyxl.load_workbook(filepath)
            for sheet in wb.sheetnames:
                ws = wb[sheet]
                for row in ws.iter_rows(values_only=True):
                    text += " ".join([str(cell) for cell in row if cell]) + "\n"
        elif ext == '.pptx':
            prs = Presentation(filepath)
            for slide in prs.slides:
                for shape in slide.shapes:
                    if shape.has_text_frame:
                        text += shape.text + "\n"
        elif ext == '.pdf':
            with pdfplumber.open(filepath) as pdf:
                for page in pdf.pages:
                    text += page.extract_text() or ""
            if not text.strip():
                images = convert_from_path(filepath)
                for img in images:
                    text += pytesseract.image_to_string(img)
        elif ext in ['.png', '.jpeg', '.jpg', '.gif']:
            img = Image.open(filepath)
            text = pytesseract.image_to_string(img)
    except Exception as e:
        logging.error(f"Error extracting text from {filepath}: {e}")
    return text

# ---- Analyze Files ----
regex_results = []
keyword_counter = Counter()

for root, dirs, files in os.walk(input_folder):
    for file in files:
        filepath = os.path.join(root, file)
        logging.info(f"Processing file: {filepath}")
        text = extract_text_from_file(filepath)
        lines = text.split('\n')

        # Regex Detection
        for pattern in regex_patterns:
            name = pattern['name']
            regex = pattern['pattern']
            matches = re.findall(regex, text)
            if matches:
                first_line = None
                for i, line in enumerate(lines, start=1):
                    if re.search(regex, line):
                        first_line = i
                        break
                regex_results.append({
                    'Regex_Name': name,
                    'Regex_Pattern': regex,
                    'Detected_Text': matches[0],
                    'Line_Number': first_line,
                    'Match_Count': len(matches)
                })

        # Keyword Extraction
        words = [w for w in re.findall(r'\b\w+\b', text) if w.lower() not in stop_words and len(w) >= min_keyword_length]
        for i in range(len(words)):
            for j in range(min_phrase_words, max_phrase_words + 1):
                if i + j <= len(words):
                    phrase = " ".join(words[i:i+j])
                    keyword_counter[phrase] += 1

# ---- Save Outputs ----
regex_df = pd.DataFrame(regex_results)
regex_df.to_csv(os.path.join(output_folder, 'regex_detections.csv'), index=False)

keywords_df = pd.DataFrame(keyword_counter.items(), columns=['Keyword', 'Count'])
keywords_df.to_csv(os.path.join(output_folder, 'keywords.csv'), index=False)

print(f"Analysis complete. Files saved in {output_folder}")
