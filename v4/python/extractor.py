from pdfminer.high_level import extract_pages
from pdfminer.layout import LTTextContainer

MAX_CHARS = 4000  # realistic Purview chunk size

def iter_text_chunks(pdf_path):
    buffer = ""

    for page in extract_pages(pdf_path):
        for element in page:
            if isinstance(element, LTTextContainer):
                buffer += element.get_text()

                if len(buffer) >= MAX_CHARS:
                    yield buffer
                    buffer = ""

    if buffer:
        yield buffer
