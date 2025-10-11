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
	# Australian BSB (Bank State Branch) Number: 6 digits, often written as XXX-XXX or XXXXXX
	bsb_regex = r"\\b\\d{3}[- ]?\\d{3}\\b"
	if re.search(bsb_regex, text):
		patterns["AU_BSB"] = bsb_regex
	patterns = {}
	# Email (generic, but relevant to AU)
	email_regex = r"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"
	if re.search(email_regex, text):
		patterns["Email"] = email_regex
	# Australian phone numbers (mobile: 04xx xxx xxx, landline: 0x xxxx xxxx)
	au_mobile_regex = r"\\b04\\d{2}[ ]?\\d{3}[ ]?\\d{3}\\b"
	if re.search(au_mobile_regex, text):
		patterns["AU_Mobile"] = au_mobile_regex
	au_landline_regex = r"\\b0[2378]\\d{1}[ ]?\\d{4}[ ]?\\d{4}\\b"
	if re.search(au_landline_regex, text):
		patterns["AU_Landline"] = au_landline_regex
	# Australian BSB (Bank State Branch) Number: 6 digits, often written as XXX-XXX or XXXXXX
	bsb_regex = r"\\b\\d{3}[- ]?\\d{3}\\b"
	if re.search(bsb_regex, text):
		patterns["AU_BSB"] = bsb_regex
	# Australian Passport Number: 1 letter followed by 7 digits
	au_passport_regex = r"\\b[A-Z]{1}\\d{7}\\b"
	if re.search(au_passport_regex, text):
		patterns["AU_Passport"] = au_passport_regex
	# Australian TFN (Tax File Number): 8 or 9 digits
	tfn_regex = r"\\b\\d{8,9}\\b"
	if re.search(tfn_regex, text):
		patterns["AU_TFN"] = tfn_regex
	# Australian Medicare Number: 10 digits, optionally with 1 digit IRN
	medicare_regex = r"\\b\\d{10}(?:\\d{1})?\\b"
	if re.search(medicare_regex, text):
		patterns["AU_Medicare"] = medicare_regex
	# Australian Driver's License (varies by state, but often 8-10 digits)
	au_dl_regex = r"\\b\\d{8,10}\\b"
	if re.search(au_dl_regex, text):
		patterns["AU_DriversLicense"] = au_dl_regex
	# Australian ABN (Australian Business Number): 11 digits
	abn_regex = r"\\b\\d{11}\\b"
	if re.search(abn_regex, text):
		patterns["AU_ABN"] = abn_regex
	# Australian ACN (Australian Company Number): 9 digits
	acn_regex = r"\\b\\d{9}\\b"
	if re.search(acn_regex, text):
		patterns["AU_ACN"] = acn_regex
	# Australian bank account number (6-10 digits, not BSB)
	au_bank_regex = r"\\b\\d{6,10}\\b"
	if re.search(au_bank_regex, text):
		patterns["AU_BankAccount"] = au_bank_regex
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
