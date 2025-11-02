import requests
from bs4 import BeautifulSoup
import csv
import re
from urllib.parse import quote

# === CONFIG ===
TRUSTED_DOMAINS = ["vertiv.com", "amazon.com", "newegg.com"]
MAX_FEATURES = 5

# === UTILITIES ===
def clean_text(text):
    """Remove extra whitespace and line breaks."""
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

# === SEARCH FUNCTIONS ===
def startpage_search_urls(product_description, domains=TRUSTED_DOMAINS):
    """Return first search-result URL per domain using StartPage HTML search."""
    headers = {"User-Agent": "Mozilla/5.0"}
    result_urls = []

    for domain in domains:
        query = f"{product_description} site:{domain}"
        search_url = f"https://www.startpage.com/do/search?q={quote(query)}&cat=web&cmd=process_search"
        try:
            resp = requests.get(search_url, headers=headers, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")

            # Look for first link in results
            link = None
            for a in soup.select("a"):
                href = a.get("href")
                if href and href.startswith("http") and domain in href:
                    link = href
                    break
            if link:
                result_urls.append(link)
        except Exception as e:
            print(f"Error searching {domain}: {e}")

    return result_urls

# === SCRAPER ===
def scrape_product_page(url):
    """Scrape brand, model, and features from a product page."""
    headers = {"User-Agent": "Mozilla/5.0"}
    data = {"brand": "", "model": "", "features": []}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")

        text = soup.get_text(separator="\n")
        lines = [clean_text(l) for l in text.split("\n") if len(clean_text(l)) > 2]

        # Heuristic: brand = first line with 'Vertiv' or known brand
        for line in lines:
            if not data["brand"] and "vertiv" in line.lower():
                data["brand"] = line
            if not data["model"] and re.search(r"GXT MT\+|3000VA", line, re.I):
                data["model"] = line
            if len(data["features"]) < MAX_FEATURES:
                # simple heuristic: lines containing certain keywords
                if any(k in line.lower() for k in ["ups", "power", "backup", "tower", "voltage"]):
                    data["features"].append(line)
    except Exception as e:
        print(f"Error scraping {url}: {e}")
    return data

# === GENERATORS ===
def generate_title(base_desc, data):
    parts = []
    if data["brand"]:
        parts.append(data["brand"])
    if data["model"]:
        parts.append(data["model"])
    parts.append(base_desc)
    keywords = ["Online UPS", "Double Conversion", "Tower", "3000VA"]
    parts.extend(keywords)
    # Use ASCII hyphen instead of en-dash
    title = " - ".join(parts)
    if len(title) > 80:
        title = title[:77] + "..."
    return title

def generate_description(base_desc, data):
    desc = clean_text(base_desc) + "\n\nKey Features:\n"
    for f in data["features"]:
        desc += f"* {f}\n"
    desc += "\nBrand: " + (data["brand"] or "N/A")
    desc += "\nModel: " + (data["model"] or "N/A")
    return desc

def generate_item_specifics(data):
    specifics = {
        "Brand": data["brand"] or "N/A",
        "Model": data["model"] or "N/A",
        "Type": "Tower UPS",
        "PowerCapacity": "3000 VA",
        "ConversionTopology": "Double Conversion (Online)"
    }
    return specifics

# === CSV OUTPUT ===
def write_csv(output_file, listing_data):
    headers = ["Title", "Description", "CategoryID"]
    item_cols = ["C:" + k for k in listing_data["item_specifics"].keys()]
    all_headers = headers + item_cols

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_headers)
        writer.writeheader()
        row = {
            "Title": listing_data["title"],
            "Description": listing_data["description"],
            "CategoryID": listing_data.get("category_id", "")
        }
        for k, v in listing_data["item_specifics"].items():
            row["C:" + k] = v
        writer.writerow(row)

# === MAIN SCRIPT ===
def main():
    base_desc = input("Enter product description: ")
    print("Searching for product pages...")
    urls = startpage_search_urls(base_desc)
    if not urls:
        print("No URLs found. Consider adding more trusted domains.")
        return
    print("Found URLs:", urls)

    # Scrape first valid URL
    data = scrape_product_page(urls[0])
    title = generate_title(base_desc, data)
    description = generate_description(base_desc, data)
    specifics = generate_item_specifics(data)

    listing_data = {
        "title": title,
        "description": description,
        "item_specifics": specifics,
        "category_id": ""  # fill if known
    }

    output_file = "ebay_listing.csv"
    write_csv(output_file, listing_data)

    print("\n=== eBay Listing Generated ===")
    print("Title:", title)
    print("Description:", description)
    print("Item Specifics:", specifics)
    print(f"CSV file saved as {output_file}")

if __name__ == "__main__":
    main()