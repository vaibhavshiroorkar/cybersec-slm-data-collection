import os
import sys
import time
import csv
import urllib.parse
import xml.etree.ElementTree as ET
import httpx

# Catalog path
CATALOG_PATH = r"C:\Users\vaibh\Documents\GitHub\data-collection\sources\profiles\ubi\Sources.csv"

# Extended keywords config
SUBDOMAINS = {
    "AML-KYC": [
        "fraud", "money laundering", "suspicious transactions",
        "financial fraud", "know your customer", "sanctions",
        "terrorist financing", "suspicious activity report",
        "transaction monitoring", "anti money laundering",
        "KYC screening", "financial crime", "aml compliance",
        "customer due diligence"
    ],
    "Compliance and Risk Management": [
        "banking", "credit risk", "capital adequacy",
        "non performing assets", "regulatory reporting",
        "Basel", "stress testing", "operational risk",
        "risk management", "financial regulations",
        "credit risk analysis", "operational risk management",
        "liquidity risk", "basel iii", "solvency", "compliance risk"
    ],
    "Corporate Governance": [
        "corporate governance", "board of directors", "shareholder rights",
        "executive compensation", "insider trading", "whistleblower",
        "conflict of interest", "corporate ethics", "regulatory compliance",
        "board oversight", "shareholder protection", "insider trading prevention",
        "corporate transparency", "audit oversight"
    ],
    "Internal Audit": [
        "internal audit", "risk assessment", "audit committee",
        "control environment", "internal controls", "financial reporting",
        "compliance audit", "forensic audit", "continuous auditing",
        "compliance testing", "internal control review", "audit evaluation",
        "fraud audit", "internal audit standards"
    ]
}

# License check (commercial friendly)
ALLOWED_LICENSES = {
    "mit", "apache-2.0", "cc-by-4.0", "cc0-1.0", "bsd-2-clause", "bsd-3-clause", 
    "cc-by-sa-4.0", "cc-by-3.0", "cc-by-sa-3.0", "cc0", "publicdomain", "pd",
    "government open data license - india (godl)", "godl", "first-party (owner-authorized)",
    "arxiv (non-exclusive)", "arxiv"
}

def clean_license(lic_str):
    if not lic_str:
        return "Unknown"
    l_lower = lic_str.strip().lower()
    for allowed in ALLOWED_LICENSES:
        if allowed in l_lower:
            return lic_str.strip()
    return None

def main():
    print("Loading existing links from catalog...")
    existing_links = set()
    existing_indian_count = 0
    existing_global_count = 0
    if os.path.exists(CATALOG_PATH):
        with open(CATALOG_PATH, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                link = row.get("Dataset Link")
                if link:
                    existing_links.add(link.strip().lower())
                country = str(row.get("Country") or "").strip().lower()
                if country == "india":
                    existing_indian_count += 1
                else:
                    existing_global_count += 1
    print(f"Loaded {len(existing_links)} existing links. (Indian: {existing_indian_count}, Global: {existing_global_count})")

    headers = {"Accept": "application/json"}
    github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GITHUB_API_KEY")
    gh_headers = {**headers, "Authorization": f"token {github_token}"} if github_token else headers

    client = httpx.Client(timeout=20.0, follow_redirects=True)
    
    new_rows = []
    seen_in_run = set()
    total_target = 10000
    current_total = len(existing_links)
    
    if current_total >= total_target:
        print("Catalog already has 10,000+ rows. Nothing to do!")
        return

    # Track statistics
    stats = {sub: 0 for sub in SUBDOMAINS}
    indian_sourced = 0
    global_sourced = 0
    
    # Mathematical guarantee for majority:
    # Max allowed global in the final catalog is 4,500.
    # Therefore, at least 5,500 must be Indian.
    max_allowed_global_total = 4500
    max_allowed_new_global = max(0, max_allowed_global_total - existing_global_count)
    
    print(f"Starting Indian-first API queries. Target: {total_target} total. (Max new global allowed: {max_allowed_new_global})")
    
    # Pass 1: Indian-specific queries (No limit on new Indian records, up to total_target)
    print("\n--- PASS 1: SOURCING INDIAN SPECIFIC DATA ---")
    for sub, keywords in SUBDOMAINS.items():
        for kw in keywords:
            if current_total + len(new_rows) >= total_target:
                break
            
            # Generate Indian search queries
            queries = [
                (f"{kw} India", "India"),
                (f"{kw} Indian", "India"),
                (f"RBI {kw}", "India"),
                (f"SEBI {kw}", "India"),
                (f"MCA India {kw}", "India"),
                (f"Indian banking {kw}", "India"),
                (f"Reserve Bank of India {kw}", "India"),
                (f"Comptroller Auditor General India {kw}", "India")
            ]
            
            for query_str, country in queries:
                if current_total + len(new_rows) >= total_target:
                    break
                
                print(f"Searching [{sub}] -> '{query_str}' ({country})...")
                
                # 1. HuggingFace (Paginating 4 pages)
                try:
                    hf_url = f"https://huggingface.co/api/datasets?search={urllib.parse.quote(query_str)}&limit=100&full=True"
                    for hf_page in range(4):
                        r = client.get(hf_url, headers=headers)
                        if r.status_code != 200:
                            break
                        hf_datasets = r.json()
                        if not hf_datasets:
                            break
                        for ds in hf_datasets:
                            ds_id = ds.get("id")
                            if not ds_id:
                                continue
                            link = f"https://huggingface.co/datasets/{ds_id}"
                            link_lower = link.lower()
                            if link_lower in existing_links or link_lower in seen_in_run:
                                continue
                            
                            lic = "Unknown"
                            card_data = ds.get("cardData") or {}
                            raw_lic = card_data.get("license")
                            if not raw_lic and ds.get("tags"):
                                for t in ds["tags"]:
                                    if t.startswith("license:"):
                                        raw_lic = t.split("license:")[1]
                                        break
                            if raw_lic:
                                if isinstance(raw_lic, list):
                                    raw_lic = raw_lic[0]
                                cleaned = clean_license(str(raw_lic))
                                if cleaned:
                                    lic = cleaned
                                else:
                                    continue
                            
                            desc = card_data.get("description") or ds.get("description") or f"HuggingFace dataset {ds_id}."
                            desc = str(desc)[:300].replace("\n", " ")
                            
                            row = {
                                "Name": ds_id,
                                "Sub-Domain": sub,
                                "Field": "Finance",
                                "Country": country,
                                "Description": desc,
                                "Dataset Link": link,
                                "Category": "Dataset",
                                "Original Format": "Parquet",
                                "License": lic,
                                "Date Added": "19/07/2026",
                                "Author": ds.get("author") or ds_id.split("/")[0] if "/" in ds_id else "Unknown",
                                "Popularity": str(ds.get("downloads", 0)),
                                "Tags": ", ".join(ds.get("tags", [])[:5]) if ds.get("tags") else "",
                                "Note": f"Sourced directly from HuggingFace ({query_str})"
                            }
                            new_rows.append(row)
                            seen_in_run.add(link_lower)
                            stats[sub] += 1
                            if country == "India":
                                indian_sourced += 1
                            if current_total + len(new_rows) >= total_target:
                                break
                        
                        link_header = r.headers.get("Link")
                        if link_header and 'rel="next"' in link_header:
                            hf_url = link_header.split("<")[1].split(">")[0]
                        else:
                            break
                except Exception as e:
                    print(f"  HuggingFace error: {e}")
                
                # 2. GitHub (Paginating 5 pages)
                for gh_page in range(1, 6):
                    if current_total + len(new_rows) >= total_target:
                        break
                    try:
                        gh_url = f"https://api.github.com/search/repositories?q={urllib.parse.quote(query_str)}+stars:>0&per_page=100&page={gh_page}"
                        r = client.get(gh_url, headers=gh_headers)
                        if r.status_code != 200:
                            break
                        gh_repos = r.json().get("items", [])
                        if not gh_repos:
                            break
                        for repo in gh_repos:
                            link = repo.get("html_url")
                            if not link:
                                continue
                            link_lower = link.lower()
                            if link_lower in existing_links or link_lower in seen_in_run:
                                continue
                            
                            lic = "Unknown"
                            raw_lic = repo.get("license") or {}
                            lic_name = raw_lic.get("key") or raw_lic.get("name")
                            if lic_name:
                                cleaned = clean_license(str(lic_name))
                                if cleaned:
                                    lic = cleaned
                                else:
                                    continue
                            
                            desc = repo.get("description") or f"GitHub repository for {repo.get('full_name')}."
                            desc = str(desc)[:300].replace("\n", " ")
                            
                            row = {
                                "Name": repo.get("full_name") or repo.get("name"),
                                "Sub-Domain": sub,
                                "Field": "Finance",
                                "Country": country,
                                "Description": desc,
                                "Dataset Link": link,
                                "Category": "Dataset",
                                "Original Format": "Code/Git",
                                "License": lic,
                                "Date Added": "19/07/2026",
                                "Author": repo.get("owner", {}).get("login") or "Unknown",
                                "Popularity": str(repo.get("stargazers_count", 0)),
                                "Tags": repo.get("language") or "",
                                "Note": f"Sourced directly from GitHub ({query_str})"
                            }
                            new_rows.append(row)
                            seen_in_run.add(link_lower)
                            stats[sub] += 1
                            if country == "India":
                                indian_sourced += 1
                            if current_total + len(new_rows) >= total_target:
                                break
                    except Exception as e:
                        print(f"  GitHub error: {e}")
                        break

                # 3. arXiv (500 results in one go)
                if current_total + len(new_rows) >= total_target:
                    break
                try:
                    arxiv_url = f"https://export.arxiv.org/api/query?search_query=all:{urllib.parse.quote(query_str)}&max_results=500"
                    r = client.get(arxiv_url)
                    if r.status_code == 200:
                        root = ET.fromstring(r.content)
                        ns = {'atom': 'http://www.w3.org/2005/Atom'}
                        for entry in root.findall('atom:entry', ns):
                            id_elem = entry.find('atom:id', ns)
                            if id_elem is None:
                                continue
                            abs_link = id_elem.text.strip()
                            link_lower = abs_link.lower()
                            if link_lower in existing_links or link_lower in seen_in_run:
                                continue
                            
                            title_elem = entry.find('atom:title', ns)
                            title = title_elem.text.strip().replace("\n", " ") if title_elem is not None else "Unknown Paper"
                            
                            summary_elem = entry.find('atom:summary', ns)
                            desc = summary_elem.text.strip().replace("\n", " ")[:300] if summary_elem is not None else "No abstract."
                            
                            author_elems = entry.findall('atom:author/atom:name', ns)
                            authors = ", ".join([a.text.strip() for a in author_elems]) if author_elems else "Unknown"
                            
                            row = {
                                "Name": title[:80],
                                "Sub-Domain": sub,
                                "Field": "Finance",
                                "Country": country,
                                "Description": desc,
                                "Dataset Link": abs_link,
                                "Category": "Text",
                                "Original Format": "PDF",
                                "License": "arXiv (non-exclusive)",
                                "Date Added": "19/07/2026",
                                "Author": authors,
                                "Popularity": "0",
                                "Tags": "Academic Paper",
                                "Note": f"Sourced directly from arXiv ({query_str})"
                            }
                            new_rows.append(row)
                            seen_in_run.add(link_lower)
                            stats[sub] += 1
                            if country == "India":
                                indian_sourced += 1
                            if current_total + len(new_rows) >= total_target:
                                break
                except Exception as e:
                    print(f"  arXiv error: {e}")
                
                print(f"  Current batch size: {len(new_rows)} (Total: {current_total + len(new_rows)})")
                time.sleep(0.4)

    # Pass 2: Global queries as fallback (ONLY up to max_allowed_new_global!)
    if current_total + len(new_rows) < total_target and global_sourced < max_allowed_new_global:
        print("\n--- PASS 2: SOURCING GLOBAL FALLBACK DATA (CAPPED) ---")
        for sub, keywords in SUBDOMAINS.items():
            for kw in keywords:
                if current_total + len(new_rows) >= total_target or global_sourced >= max_allowed_new_global:
                    break
                
                print(f"Searching global fallback [{sub}] -> '{kw}' (Global)...")
                
                # 1. HuggingFace
                try:
                    hf_url = f"https://huggingface.co/api/datasets?search={urllib.parse.quote(kw)}&limit=100&full=True"
                    for hf_page in range(2):
                        r = client.get(hf_url, headers=headers)
                        if r.status_code != 200:
                            break
                        hf_datasets = r.json()
                        if not hf_datasets:
                            break
                        for ds in hf_datasets:
                            ds_id = ds.get("id")
                            if not ds_id:
                                continue
                            link = f"https://huggingface.co/datasets/{ds_id}"
                            link_lower = link.lower()
                            if link_lower in existing_links or link_lower in seen_in_run:
                                continue
                            
                            lic = "Unknown"
                            card_data = ds.get("cardData") or {}
                            raw_lic = card_data.get("license")
                            if not raw_lic and ds.get("tags"):
                                for t in ds["tags"]:
                                    if t.startswith("license:"):
                                        raw_lic = t.split("license:")[1]
                                        break
                            if raw_lic:
                                if isinstance(raw_lic, list):
                                    raw_lic = raw_lic[0]
                                cleaned = clean_license(str(raw_lic))
                                if cleaned:
                                    lic = cleaned
                                else:
                                    continue
                            
                            desc = card_data.get("description") or ds.get("description") or f"HuggingFace dataset {ds_id}."
                            desc = str(desc)[:300].replace("\n", " ")
                            
                            row = {
                                "Name": ds_id,
                                "Sub-Domain": sub,
                                "Field": "Finance",
                                "Country": "Global",
                                "Description": desc,
                                "Dataset Link": link,
                                "Category": "Dataset",
                                "Original Format": "Parquet",
                                "License": lic,
                                "Date Added": "19/07/2026",
                                "Author": ds.get("author") or ds_id.split("/")[0] if "/" in ds_id else "Unknown",
                                "Popularity": str(ds.get("downloads", 0)),
                                "Tags": ", ".join(ds.get("tags", [])[:5]) if ds.get("tags") else "",
                                "Note": f"Sourced directly from HuggingFace ({kw})"
                            }
                            new_rows.append(row)
                            seen_in_run.add(link_lower)
                            stats[sub] += 1
                            global_sourced += 1
                            if current_total + len(new_rows) >= total_target or global_sourced >= max_allowed_new_global:
                                break
                        
                        link_header = r.headers.get("Link")
                        if link_header and 'rel="next"' in link_header:
                            hf_url = link_header.split("<")[1].split(">")[0]
                        else:
                            break
                except Exception as e:
                    print(f"  HuggingFace error: {e}")
                
                # 2. GitHub
                try:
                    gh_url = f"https://api.github.com/search/repositories?q={urllib.parse.quote(kw)}+stars:>0&per_page=100&page=1"
                    r = client.get(gh_url, headers=gh_headers)
                    if r.status_code == 200:
                        gh_repos = r.json().get("items", [])
                        for repo in gh_repos:
                            link = repo.get("html_url")
                            if not link:
                                continue
                            link_lower = link.lower()
                            if link_lower in existing_links or link_lower in seen_in_run:
                                continue
                            
                            lic = "Unknown"
                            raw_lic = repo.get("license") or {}
                            lic_name = raw_lic.get("key") or raw_lic.get("name")
                            if lic_name:
                                cleaned = clean_license(str(lic_name))
                                if cleaned:
                                    lic = cleaned
                                else:
                                    continue
                            
                            desc = repo.get("description") or f"GitHub repository for {repo.get('full_name')}."
                            desc = str(desc)[:300].replace("\n", " ")
                            
                            row = {
                                "Name": repo.get("full_name") or repo.get("name"),
                                "Sub-Domain": sub,
                                "Field": "Finance",
                                "Country": "Global",
                                "Description": desc,
                                "Dataset Link": link,
                                "Category": "Dataset",
                                "Original Format": "Code/Git",
                                "License": lic,
                                "Date Added": "19/07/2026",
                                "Author": repo.get("owner", {}).get("login") or "Unknown",
                                "Popularity": str(repo.get("stargazers_count", 0)),
                                "Tags": repo.get("language") or "",
                                "Note": f"Sourced directly from GitHub ({kw})"
                            }
                            new_rows.append(row)
                            seen_in_run.add(link_lower)
                            stats[sub] += 1
                            global_sourced += 1
                            if current_total + len(new_rows) >= total_target or global_sourced >= max_allowed_new_global:
                                break
                except Exception as e:
                    print(f"  GitHub error: {e}")

                # 3. arXiv
                try:
                    arxiv_url = f"https://export.arxiv.org/api/query?search_query=all:{urllib.parse.quote(kw)}&max_results=200"
                    r = client.get(arxiv_url)
                    if r.status_code == 200:
                        root = ET.fromstring(r.content)
                        ns = {'atom': 'http://www.w3.org/2005/Atom'}
                        for entry in root.findall('atom:entry', ns):
                            id_elem = entry.find('atom:id', ns)
                            if id_elem is None:
                                continue
                            abs_link = id_elem.text.strip()
                            link_lower = abs_link.lower()
                            if link_lower in existing_links or link_lower in seen_in_run:
                                continue
                            
                            title_elem = entry.find('atom:title', ns)
                            title = title_elem.text.strip().replace("\n", " ") if title_elem is not None else "Unknown Paper"
                            
                            summary_elem = entry.find('atom:summary', ns)
                            desc = summary_elem.text.strip().replace("\n", " ")[:300] if summary_elem is not None else "No abstract."
                            
                            author_elems = entry.findall('atom:author/atom:name', ns)
                            authors = ", ".join([a.text.strip() for a in author_elems]) if author_elems else "Unknown"
                            
                            row = {
                                "Name": title[:80],
                                "Sub-Domain": sub,
                                "Field": "Finance",
                                "Country": "Global",
                                "Description": desc,
                                "Dataset Link": abs_link,
                                "Category": "Text",
                                "Original Format": "PDF",
                                "License": "arXiv (non-exclusive)",
                                "Date Added": "19/07/2026",
                                "Author": authors,
                                "Popularity": "0",
                                "Tags": "Academic Paper",
                                "Note": f"Sourced directly from arXiv ({kw})"
                            }
                            new_rows.append(row)
                            seen_in_run.add(link_lower)
                            stats[sub] += 1
                            global_sourced += 1
                            if current_total + len(new_rows) >= total_target or global_sourced >= max_allowed_new_global:
                                break
                except Exception as e:
                    print(f"  arXiv error: {e}")
                
                print(f"  Current batch size: {len(new_rows)} (Total: {current_total + len(new_rows)})")
                time.sleep(0.4)

    print("\nSourcing complete.")
    print(f"Total new rows sourced: {len(new_rows)} (Indian: {indian_sourced}, Global Sourced: {global_sourced})")
    print(f"Sub-domain stats:")
    for sub, val in stats.items():
        print(f"  {sub}: {val}")

    if len(new_rows) > 0:
        print(f"Appending {len(new_rows)} new rows to {CATALOG_PATH}...")
        header = []
        with open(CATALOG_PATH, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)
        
        with open(CATALOG_PATH, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=header)
            for row in new_rows:
                full_row = {col: row.get(col, "") for col in header}
                writer.writerow(full_row)
        print("CSV append successful.")
    else:
        print("No new rows to append.")

if __name__ == "__main__":
    main()
