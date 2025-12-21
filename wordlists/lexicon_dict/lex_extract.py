#!/usr/bin/env python3

import os
import re
import csv
import argparse
import warnings
import logging
from functools import lru_cache
from collections import Counter

import pdfplumber
import docx
from wordfreq import zipf_frequency  # dictionary-based word validity scoring

warnings.filterwarnings("ignore")

STOPWORDS = set("""
a an the and or but if while although however therefore moreover thus this that
it you me him her them us we our your their mine yours his hers theirs
of to in for from by on at with without about as into onto between under
is am are was were be been being
can will would should could may might must do does did done having have has
so very just not only again still more less most least
""".split())

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
NUMBER_RE = re.compile(r"\b\d+\b")
WORD_RE = re.compile(r"[a-z]{5,}")  # minimum 5 letters

# Minimum lexical score: 2.0 = uncommon but real word
# 4.0 = moderately common word
LEXICON_MIN_SCORE = 2.0
SUPPORTED_EXTENSIONS = (".pdf", ".csv", ".docx", ".txt")


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)


@lru_cache(maxsize=100_000)
def is_real_word(word):
    score = zipf_frequency(word, "en")
    return score >= LEXICON_MIN_SCORE


def extract_from_pdf(path):
    parts = []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with pdfplumber.open(path) as pdf:
                for page in pdf.pages:
                    try:
                        t = page.extract_text()
                        if t:
                            parts.append(t)
                    except Exception:
                        continue
    except Exception:
        pass
    return " ".join(parts)


def extract_from_csv(path):
    parts = []
    try:
        with open(path, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                for cell in row:
                    if isinstance(cell, str):
                        parts.append(cell)
    except Exception:
        pass
    return " ".join(parts)


def extract_from_docx(path):
    parts = []
    try:
        doc = docx.Document(path)
        for p in doc.paragraphs:
            parts.append(p.text)
    except Exception:
        pass
    return " ".join(parts)


def extract_from_txt(path):
    parts = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            parts.append(f.read())
    except Exception:
        pass
    return " ".join(parts)


def extract_text_from_file(path):
    ext = path.lower()
    try:
        if ext.endswith(".pdf"):
            return extract_from_pdf(path)
        if ext.endswith(".csv"):
            return extract_from_csv(path)
        if ext.endswith(".docx"):
            return extract_from_docx(path)
        if ext.endswith(".txt"):
            return extract_from_txt(path)
    except Exception:
        return ""
    return ""


def filter_token(token):
    return (
        token
        and token not in STOPWORDS
        and not EMAIL_RE.match(token)
        and not NUMBER_RE.match(token)
        and is_real_word(token)
    )


def extract_words(text):
    raw_words = WORD_RE.findall(text.lower())
    return [t for t in raw_words if filter_token(t)]


def walk_directory(indir):
    for root, dirs, files in os.walk(indir):
        for f in files:
            if f.lower().endswith(SUPPORTED_EXTENSIONS):
                yield os.path.join(root, f)


def main():
    parser = argparse.ArgumentParser(
        description="Extract meaningful lexicon words from PDF/DOCX/CSV/TXT files."
    )
    parser.add_argument("--indir", required=True, help="Input directory")
    parser.add_argument("--outdir", required=True, help="Output directory")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print debug details while processing files.",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    os.makedirs(args.outdir, exist_ok=True)
    outfile = os.path.join(args.outdir, "lexicon.csv")

    word_counts = Counter()
    paths = list(walk_directory(args.indir))

    if not paths:
        logging.warning("No supported files found under %s", args.indir)

    for idx, path in enumerate(paths, start=1):
        logging.info("Processing file %s/%s: %s", idx, len(paths), path)
        text = extract_text_from_file(path)
        if text:
            words = extract_words(text)
            word_counts.update(words)
            logging.debug("Added %s words from %s", len(words), path)
        else:
            logging.debug("No text extracted from %s", path)

    with open(outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["word"])
        for word in word_counts:
            writer.writerow([word])

    logging.info(
        "Done. Extracted %s unique valid dictionary words \u2192 %s",
        len(word_counts),
        outfile,
    )


if __name__ == "__main__":
    main()
