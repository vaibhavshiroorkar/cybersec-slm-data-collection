#!/usr/bin/env python3
"""Catalog of sources for the corpus. One row = one dataset / scrape target.

DATASETS  -> fetch.py   (hf | kaggle | url | github)
PDFS      -> scrape.py  (one record per page)
FEEDS     -> scrape.py  (JSON feeds, normalised to {source,url,license,text})
SITES     -> scrape_html.py (BFS HTML crawl)
APIS      -> fetch_nvd.py (paginated REST APIs)
XML_FEEDS -> scrape.py  (XML downloads needing custom parsing)

TABULAR_ONLY lists feature-matrix datasets that are intentionally excluded from
the SLM text pipeline.  They can still be used for a separate classification
model but produce no usable text field.
"""

from .common import GOV_IN, GOV_US, MITRE

CWE_TERMS = "MITRE CWE Terms of Use (free use with attribution)"

# ---------------------------------------------------------------------------
# TEXT-BEARING DATASETS  (included in SLM pipeline)
# ---------------------------------------------------------------------------
# kind: hf | kaggle | github | url
# each: (kind, ref, domain, description, license, [url for github/url])
DATASETS = [
    # ---------------- Application Security ----------------
    ("kaggle", "cyberprince/web-application-payloads-dataset",
     "Application Security", "Web attack payload strings", "to-verify"),
    ("hf", "AlicanKiraz0/Cybersecurity-Dataset-v1", "Application Security",
     "Web-sec Q&A (XSS/SQLi/CSRF)", "to-verify"),
    ("kaggle", "ispangler/csic-2010-web-application-attacks",
     "Application Security", "HTTP CSIC 2010 web attack requests", "to-verify"),
    ("kaggle", "syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning",
     "Application Security", "XSS payload strings", "to-verify"),

    # ---------------- Threat Intelligence ----------------
    ("hf", "zefang-liu/phishing-email-dataset", "Threat Intelligence",
     "Phishing vs benign emails", "to-verify"),
    ("hf", "darkknight25/phishing_benign_email_dataset", "Threat Intelligence",
     "Phishing/benign email", "to-verify"),
    ("kaggle", "shashwatwork/web-page-phishing-detection-dataset",
     "Threat Intelligence", "Web-page phishing features + URLs", "to-verify"),
    ("url", "phiusiil-phishing-url", "Threat Intelligence",
     "UCI PhiUSIIL phishing URLs (235k)", "CC BY 4.0",
     "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"),
    ("kaggle", "sid321axn/malicious-urls-dataset",
     "Penetration Testing and Vulnerability Management",
     "651k malicious URL strings", "to-verify"),
    ("hf", "ealvaradob/phishing-dataset", "Threat Intelligence",
     "Phishing URLs / emails / HTML", "to-verify"),

    # ---------------- Incident Response ----------------
    ("hf", "darkknight25/Incident_Response_Playbook_Dataset",
     "Incident Response and Forensics", "IR playbooks", "to-verify"),
    ("kaggle", "Microsoft/microsoft-security-incident-prediction",
     "Incident Response and Forensics", "GUIDE SOC incident triage", "cc-by-4.0"),

    # ---------------- Cloud Security ----------------
    ("kaggle", "nobukim/aws-cloudtrails-dataset-from-flaws-cloud",
     "Cloud Security", "AWS CloudTrail attack logs (semantic JSON events)", "to-verify"),

    # ---------------- Data Security & Privacy ----------------
    ("hf", "ai4privacy/pii-masking-200k", "Data Security and Privacy",
     "PII detection / masking (200k)", "to-verify"),
    ("hf", "ai4privacy/pii-masking-300k", "Data Security and Privacy",
     "PII detection / masking (300k)", "to-verify"),
]

# ---------------------------------------------------------------------------
# TABULAR-ONLY DATASETS  (excluded from SLM — feature matrices, no text)
# ---------------------------------------------------------------------------
# These are kept for reference / a future ML classification pipeline.
# DO NOT add them to DATASETS — they produce no text field and will be
# silently dropped by the anomaly stage.
TABULAR_ONLY = [
    # Malware PE / Android feature matrices
    ("kaggle", "joebeachcapital/windows-malwares",
     "Windows PE malware numeric features"),
    ("kaggle", "shashwatwork/android-malware-dataset-for-machine-learning",
     "Android malware Drebin feature vectors"),
    ("kaggle", "ang3loliveira/malware-analysis-datasets-top1000-pe-imports",
     "Top-1000 PE import feature counts"),
    ("kaggle", "dannyrevaldo/android-malware-detection-dataset",
     "Android malware detection feature matrix"),
    ("kaggle", "subhajournal/android-ransomware-detection",
     "Android ransomware flow features"),
    ("kaggle", "saurabhshahane/classification-of-malwares",
     "CLaMP PE malware classification features"),
    ("kaggle", "saurabhshahane/android-malware-dataset",
     "Android malware static feature matrix"),
    ("kaggle", "nsaravana/malware-detection",
     "Malware detection numeric features"),
    # Network flow feature matrices
    ("kaggle", "mrwellsdavid/unsw-nb15", "UNSW-NB15 network flow features"),
    ("kaggle", "dhoogla/unswnb15", "UNSW-NB15 cleaned network flow features"),
    ("kaggle", "galaxyh/kdd-cup-1999-data", "KDD Cup 1999 network features"),
    ("kaggle", "aikenkazin/ml-edge-iiot-dataset", "Edge-IIoT flow features"),
    ("kaggle", "dhoogla/cicids2017", "CICIDS2017 network flow features"),
    ("kaggle", "dhoogla/cicddos2019", "CIC-DDoS2019 flow features"),
    # IAM / behavioral numeric features
    ("kaggle", "dasgroup/rba-dataset", "Risk-based auth numeric signals (3.3M)"),
    ("kaggle", "lako65/ssh-brute-force-ipuserpassword",
     "SSH brute-force IP/user/password pairs"),
    ("kaggle", "rasikaekanayakadevlk/user-activity-dataset",
     "Behavioral auth numeric signals"),
    # Security operations numeric features
    ("kaggle", "dnkumars/cybersecurity-intrusion-detection-dataset",
     "Login/session intrusion numeric features"),
    ("kaggle", "rasikaekanayakadevlk/security-monitoring-and-user-management-dataset",
     "Security monitoring numeric signals"),
    # Cloud features
    ("kaggle", "alaakhaledd/cloud-security-dataset",
     "Cloud security telemetry features"),
    # UCI numeric feature sets
    ("url", "uci-phishing-websites",
     "UCI phishing websites (30 numeric features only)"),
    ("url", "dike-malware", "DikeDataset malicious PE labels (numeric)"),
    ("url", "dike-benign", "DikeDataset benign PE labels (numeric)"),
]

# ---------------------------------------------------------------------------
# PDFS  (one record per page)
# ---------------------------------------------------------------------------
PDFS = [
    ("Incident Response and Forensics", "nist-sp800-61",
     "NIST SP 800-61r2 Incident Handling Guide", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf"),
    ("Incident Response and Forensics", "nist-sp800-86",
     "NIST SP 800-86 Forensic Techniques", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf"),
    ("Incident Response and Forensics", "nist-sp800-184",
     "NIST SP 800-184 Cybersecurity Event Recovery", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-184.pdf"),
    ("Data Security and Privacy", "nist-sp800-122",
     "NIST SP 800-122 Protecting PII", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-122.pdf"),
    ("Data Security and Privacy", "india-dpdp-act-2023",
     "India Digital Personal Data Protection Act 2023", GOV_IN,
     "https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf"),
    ("Governance, Risk and Compliance", "nist-sp800-53r5",
     "NIST SP 800-53r5 Security & Privacy Controls", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf"),
    ("Governance, Risk and Compliance", "nist-sp800-37r2",
     "NIST SP 800-37r2 Risk Management Framework", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf"),
    ("Governance, Risk and Compliance", "nist-sp800-30r1",
     "NIST SP 800-30r1 Guide for Conducting Risk Assessments", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf"),
    ("Governance, Risk and Compliance", "india-it-act-2000",
     "India Information Technology Act 2000", GOV_IN,
     "https://www.indiacode.nic.in/bitstream/123456789/13116/1/it_act_2000_updated.pdf"),
    ("Penetration Testing and Vulnerability Management", "nist-sp800-115",
     "NIST SP 800-115 Security Testing", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf"),
    ("Penetration Testing and Vulnerability Management", "nist-sp800-40r4",
     "NIST SP 800-40r4 Enterprise Patch Management", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-40r4.pdf"),
    ("Cryptography", "nist-sp800-57",
     "NIST SP 800-57 Key Management", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf"),
    ("Cryptography", "nist-fips-203-mlkem",
     "NIST FIPS 203 ML-KEM (PQC)", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf"),
    ("Cryptography", "nist-fips-204-mldsa",
     "NIST FIPS 204 ML-DSA (PQC)", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf"),
    ("Cryptography", "nist-fips-205-slhdsa",
     "NIST FIPS 205 SLH-DSA (PQC)", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf"),
    ("Cryptography", "nist-sp800-208",
     "NIST SP 800-208 Hash-Based Signatures", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf"),
    ("Identity Access and Management", "nist-sp800-63b",
     "NIST SP 800-63B Digital Identity", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf"),
    ("Security Operations", "nist-sp800-92",
     "NIST SP 800-92 Log Management", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf"),
    ("Network Security", "nist-sp800-94",
     "NIST SP 800-94 IDS/IPS", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-94.pdf"),
    ("Threat Intelligence", "nist-sp800-150",
     "NIST SP 800-150 Cyber Threat Information Sharing", GOV_US,
     "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-150.pdf"),
]

# ---------------------------------------------------------------------------
# SITES  (BFS HTML crawl — robots.txt verified)
# ---------------------------------------------------------------------------
# (domain, slug, start_url, license, use_js, max_pages, allow_prefix, description)
SITES = [
    ("Threat Intelligence", "mitre-attack-web",
     "https://attack.mitre.org/techniques/enterprise/",
     "MITRE ATT&CK Terms (free w/ attribution)", False, 70,
     "https://attack.mitre.org/techniques/", "MITRE ATT&CK technique pages"),
    ("Penetration Testing and Vulnerability Management", "capec-web",
     "https://capec.mitre.org/data/definitions/1000.html",
     "MITRE CAPEC Terms (free w/ attribution)", False, 70,
     "https://capec.mitre.org/data/definitions/", "MITRE CAPEC attack patterns"),
]

# ---------------------------------------------------------------------------
# FEEDS  (single-URL JSON, normalised to {source,url,license,text})
# ---------------------------------------------------------------------------
# (domain, slug, title, license, url, json_key)
FEEDS = [
    ("Threat Intelligence", "cisa-kev",
     "CISA Known Exploited Vulnerabilities", "Public Domain (CISA)",
     "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
     "vulnerabilities"),
    ("Threat Intelligence", "mitre-attack",
     "MITRE ATT&CK Enterprise", MITRE,
     "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
     "objects"),
    ("Threat Intelligence", "mitre-attack-mobile",
     "MITRE ATT&CK Mobile", MITRE,
     "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
     "objects"),
    ("Threat Intelligence", "mitre-attack-ics",
     "MITRE ATT&CK ICS", MITRE,
     "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
     "objects"),
]

# ---------------------------------------------------------------------------
# APIS  (paginated REST APIs — handled by fetch_nvd.py)
# ---------------------------------------------------------------------------
# (domain, slug, title, license, base_url)
APIS = [
    ("Penetration Testing and Vulnerability Management", "nvd-cve",
     "NVD National Vulnerability Database", GOV_US,
     "https://services.nvd.nist.gov/rest/json/cves/2.0"),
]

# ---------------------------------------------------------------------------
# XML_FEEDS  (ZIP + XML downloads needing custom parsing)
# ---------------------------------------------------------------------------
# (domain, slug, title, license, url)
XML_FEEDS = [
    ("Penetration Testing and Vulnerability Management", "mitre-cwe",
     "MITRE Common Weakness Enumeration", CWE_TERMS,
     "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"),
]
