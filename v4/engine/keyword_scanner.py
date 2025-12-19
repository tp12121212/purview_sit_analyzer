from typing import Dict, List


def load_weighted_lexicon(csv_path):
    """
    Pipe-delimited:
    keyword|weight
    """
    lexicon: Dict[str, float] = {}

    with open(csv_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "|" not in line:
                continue
            word, weight = line.split("|", 1)
            lexicon[word] = float(weight)

    return lexicon


def find_adjacent_keyword_pairs(text: str, lexicon: Dict[str, float]) -> List[dict]:
    """
    Only matches:
      <word><space><word>

    No punctuation, no normalization, no token repair.
    """
    results = []

    tokens = text.split(" ")

    for i in range(len(tokens) - 1):
        w1 = tokens[i]
        w2 = tokens[i + 1]

        if w1 in lexicon and w2 in lexicon:
            phrase = f"{w1} {w2}"
            weight = lexicon[w1] + lexicon[w2]

            results.append({
                "phrase": phrase,
                "weight": weight
            })

    return results
