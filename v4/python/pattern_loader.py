import json

def load_patterns(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return [
        {"name": p["name"], "pattern": p["pattern"]}
        for p in data
        if "pattern" in p
    ]
