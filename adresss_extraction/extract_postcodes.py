import re
import csv
import sys
from PyPDF2 import PdfReader

def extract_postcodes(pdf_path, output_csv):
    # Regex pattern for suburb, state, postcode
    pattern = re.compile(
        r'([A-Z][A-Z-\s]+?)\s+'
        r'(NSW|VIC|QLD|SA|WA|TAS|NT|ACT)\s+'
        r'(\d{4})'
    )

    data = set()
    reader = PdfReader(pdf_path)

    for page in reader.pages:
        text = page.extract_text()
        if not text:
            continue

        for match in pattern.findall(text):
            suburb = match[0].strip()
            # Clean notes like PO Boxes, Locked Bags, GPO
            suburb = re.sub(r'.*(PO Box|Locked Bag|GPO).*', '', suburb, flags=re.IGNORECASE).strip()
            state, postcode = match[1], match[2]
            if suburb:  # Only add non-empty suburbs
                data.add((suburb, state, postcode))

    # Sort alphabetically by suburb
    sorted_data = sorted(data, key=lambda x: x[0])

    # Write to CSV
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Suburb', 'State', 'Postcode'])
        writer.writerows(sorted_data)

    print(f"Extraction complete. Saved to {output_csv}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python extract_postcodes.py <input_pdf> <output_csv>")
    else:
        extract_postcodes(sys.argv[1], sys.argv[2])
