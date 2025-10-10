#!/usr/bin/env python3
"""
Script: generate_sit_from_pdf.py
Extracts text from a PDF, analyzes for sensitive patterns, suggests Boost 5.1-compliant regexes and keywords, and outputs a Microsoft 365 DLP SIT XML definition and PowerShell code to create the SIT.
"""
import sys
import os
import re
from collections import Counter

try:
	import pdfplumber
except ImportError:
	print("Please install pdfplumber: pip install pdfplumber")
	sys.exit(1)

def extract_text_from_pdf(pdf_path):
	text = ""
	with pdfplumber.open(pdf_path) as pdf:
		for page in pdf.pages:
			text += page.extract_text() or ""
	return text

def suggest_keywords(text, top_n=20):
	words = re.findall(r"\b\w{5,}\b", text)
	common = Counter(words).most_common(top_n)
	return [w for w, _ in common]

def suggest_regex_patterns(text):
	patterns = {}
	email_regex = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
	if re.search(email_regex, text):
		patterns["Email"] = email_regex
	phone_regex = r"\\b(?:\\+?\\d{1,3}[ -]?)?(?:\\(\\d{2,4}\\)[ -]?|\\d{2,4}[ -]?)?\\d{3,4}[ -]?\\d{3,4}\\b"
	if re.search(phone_regex, text):
		patterns["Phone"] = phone_regex
	# Add more pattern suggestions as needed
	return patterns

def create_sit_definition(name, regexes, keywords):
	# Microsoft 365 DLP SIT XML format
	primary_regex = list(regexes.values())[0] if regexes else r"[A-Za-z0-9]{8,}"
	xml = f'''<?xml version="1.0" encoding="utf-8"?>
<SensitiveInformationType id="{name}" publisher="Custom">
  <Rules>
	<Rule id="{name}_Rule" minCount="1" patternProximity="300">
	  <Match>
		<Regex>
		  <Pattern>{primary_regex}</Pattern>
		</Regex>
		<Keywords>
		  {''.join(f'<Keyword>{kw}</Keyword>' for kw in keywords)}
		</Keywords>
	  </Match>
	</Rule>
  </Rules>
</SensitiveInformationType>
'''
	return xml

def generate_powershell_code(sit_file):
	ps_code = f"""
# PowerShell code to create Microsoft 365 DLP SIT
Connect-IPPSession
$xml = Get-Content -Raw -Path '{sit_file}'
New-DlpSensitiveInformationType -Name "$(Split-Path '{sit_file}' -Leaf)" -Xml $xml
"""
	return ps_code

def main(pdf_path, output_prefix):
	text = extract_text_from_pdf(pdf_path)
	keywords = suggest_keywords(text)
	regexes = suggest_regex_patterns(text)
	sit_name = os.path.splitext(os.path.basename(pdf_path))[0] + "_SIT"
	sit_xml = create_sit_definition(sit_name, regexes, keywords)
	sit_file = f"{output_prefix}_sit.xml"
	with open(sit_file, "w", encoding="utf-8") as f:
		f.write(sit_xml)
	ps_code = generate_powershell_code(sit_file)
	ps_file = f"{output_prefix}_create_sit.ps1"
	with open(ps_file, "w", encoding="utf-8") as f:
		f.write(ps_code)
	print(f"SIT definition written to {sit_file}")
	print(f"PowerShell code written to {ps_file}")

if __name__ == "__main__":
	if len(sys.argv) < 3:
		print("Usage: python generate_sit_from_pdf.py <source.pdf> <output_prefix>")
		sys.exit(1)
	main(sys.argv[1], sys.argv[2])
