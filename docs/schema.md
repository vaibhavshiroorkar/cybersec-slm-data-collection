# Raw Data Schema (JSONL)

Each line in a .jsonl file is one record with these fields:

- source_id: unique identifier for the source (e.g. "nvd", "mitre_attack")
- url: where the data came from
- text: the raw text content
- domain_category: e.g. "vulnerability", "malware", "threat_intel"
- collection_date: YYYY-MM-DD
- license: license name e.g. "CC-BY-4.0"
- language: e.g. "en"

# Example Record

{"source_id": "nvd", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234", "text": "A buffer overflow vulnerability in...", "domain_category": "vulnerability", "collection_date": "2024-01-15", "license": "public_domain", "language": "en"}