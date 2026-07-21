import os
import re
import csv
import json
import httpx
import pymupdf

BASE_DIR = r"C:\Users\vaibh\Documents\GitHub\data-collection\data\ubi\raw"
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

SOURCES = [
    {
        "slug": "ubi-regulatory-disclosures",
        "domain": "Compliance and Risk Management",
        "url": "https://www.unionbankofindia.bank.in/en/common/regulatory-disclosures",
        "description": "Basel III Pillar 3 disclosures and regulatory filings (own content)"
    },
    {
        "slug": "ubi-investor-relations",
        "domain": "Corporate Governance",
        "url": "https://www.unionbankofindia.bank.in/en/common/investor-relations",
        "description": "Annual reports, Code of Corporate Governance, secretarial compliance reports (own content)"
    },
    {
        "slug": "ubi-policies",
        "domain": "Compliance and Risk Management",
        "url": "https://www.unionbankofindia.bank.in/en/subcatlist/policy",
        "description": "Published bank policies incl. Risk Management Policy (own content)"
    }
]

def clean_text(text):
    return text.replace("\r", "").replace("\n", " ").strip()

def process_source(src, client):
    slug = src["slug"]
    domain = src["domain"]
    url = src["url"]
    desc = src["description"]
    
    print(f"\nProcessing {slug} (crawling {url})...")
    
    # 1. Fetch HTML index page
    try:
        r = client.get(url, headers=HEADERS)
        if r.status_code != 200:
            print(f"  Failed to fetch index page: HTTP {r.status_code}")
            return
        html = r.text
    except Exception as e:
        print(f"  Error fetching index page: {e}")
        return
        
    # 2. Extract PDF links
    raw_links = re.findall(r'href=[\'"]([^\'"]+pdf[^\'"]*)[\'"]', html, re.IGNORECASE)
    pdf_links = []
    for link in raw_links:
        link = link.strip()
        if not link.startswith("http"):
            # relative link
            if not link.startswith("/"):
                link = "/" + link
            link = "https://www.unionbankofindia.bank.in" + link
        if link not in pdf_links:
            pdf_links.append(link)
            
    print(f"  Found {len(pdf_links)} PDF files.")
    
    # 3. Create target directory
    folder = os.path.join(BASE_DIR, domain, slug)
    os.makedirs(folder, exist_ok=True)
    
    # Create _SOURCE.json
    with open(os.path.join(folder, "_SOURCE.json"), "w", encoding="utf-8") as f:
        json.dump({"source": desc, "url": url, "license": "First-party (owner-authorized)"}, f, indent=2)
        
    out_path = os.path.join(folder, f"{slug}.jsonl")
    records_written = 0
    
    # 4. Download and parse each PDF
    for i, pdf_url in enumerate(pdf_links, 1):
        print(f"  [{i}/{len(pdf_links)}] Downloading {pdf_url}...")
        try:
            resp = client.get(pdf_url, headers=HEADERS, timeout=30.0)
            if resp.status_code != 200:
                print(f"    Failed to download: HTTP {resp.status_code}")
                continue
                
            pdf_bytes = resp.content
            if pdf_bytes[:4] != b"%PDF":
                print(f"    Downloaded file is not a valid PDF")
                continue
                
            # Extract text
            doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
            pdf_records = []
            for page_num, page in enumerate(doc, 1):
                page_text = page.get_text().strip()
                if page_text:
                    rec = {
                        "source": desc,
                        "url": pdf_url,
                        "license": "First-party (owner-authorized)",
                        "text": page_text
                    }
                    pdf_records.append(rec)
            doc.close()
            
            if pdf_records:
                with open(out_path, "a", encoding="utf-8") as f:
                    for rec in pdf_records:
                        f.write(json.dumps(rec) + "\n")
                records_written += len(pdf_records)
                print(f"    Extracted {len(pdf_records)} text pages.")
            else:
                print(f"    No text extracted (scanned image?)")
                
        except Exception as e:
            print(f"    Error processing PDF: {e}")
            
    print(f"  Finished {slug}. Wrote {records_written} page records to {out_path}.")

def main():
    client = httpx.Client(follow_redirects=True, timeout=15.0)
    for src in SOURCES:
        process_source(src, client)
    client.close()
    print("\nAll Union Bank PDF extractions completed.")

if __name__ == "__main__":
    main()
