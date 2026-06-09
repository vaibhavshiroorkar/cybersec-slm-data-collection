# Master Source List

Name: NVD - National Vulnerability Database
Category: API
URL: https://nvd.nist.gov/developers/vulnerabilities
Size: 250,000+ CVE records
Format: JSON
Access: Free API key required
Why Useful: Gold standard CVE descriptions, severity scores, affected products

Name: MITRE ATT&CK
Category: API / Domain-Specific
URL: https://attack.mitre.org/
Size: 700+ techniques and sub-techniques
Format: JSON (STIX format)
Access: Free, no key required
Why Useful: Detailed descriptions of attacker tactics, techniques, and procedures

Name: AlienVault OTX - Open Threat Exchange
Category: API / Threat Intelligence
URL: https://otx.alienvault.com/api
Size: Millions of threat indicators and pulse reports
Format: JSON
Access: Free API key required
Why Useful: Community threat reports, malware analysis, and IOCs with rich text descriptions

Name: Abuse.ch
Category: API / Domain-Specific
URL: https://abuse.ch/
Size: Millions of malware and botnet records
Format: JSON / CSV
Access: Free, no key required
Why Useful: Malware samples, botnet tracking, ransomware tracker with descriptive text

Name: CIRCL CVE Search
Category: API
URL: https://cve.circl.lu/api/
Size: Full CVE database mirror
Format: JSON
Access: Free, no key required
Why Useful: Alternative CVE source with extra metadata, good backup to NVD

Name: VirusTotal
Category: API / Threat Intelligence
URL: https://developers.virustotal.com/
Size: Millions of malware reports
Format: JSON
Access: Free tier API key required
Why Useful: Malware behavior reports and file analysis descriptions

Name: Shodan
Category: API
URL: https://developer.shodan.io/
Size: Billions of device records
Format: JSON
Access: Free tier API key required
Why Useful: Internet exposure data, vulnerability context, device descriptions

Name: MITRE CWE
Category: API / Domain-Specific
URL: https://cwe.mitre.org/data/
Size: 900+ weakness entries
Format: XML / JSON
Access: Free, no key required
Why Useful: Software weakness descriptions and examples, complements CVE data

Name: HuggingFace Cybersecurity Datasets
Category: Open Dataset
URL: https://huggingface.co/datasets?search=cybersecurity
Size: Varies per dataset, multiple available
Format: JSON / CSV / Parquet
Access: Free, datasets library
Why Useful: Ready to use, no scraping needed, covers phishing, malware, intrusion detection

Name: Kaggle Cybersecurity Datasets
Category: Open Dataset
URL: https://www.kaggle.com/datasets?search=cybersecurity
Size: Varies per dataset
Format: CSV / JSON
Access: Free, Kaggle API key required
Why Useful: Community datasets on breaches, phishing, malware, network traffic

Name: SecLists
Category: Domain-Specific Repository
URL: https://github.com/danielmiessler/SecLists
Size: ~1GB
Format: TXT / CSV
Access: Free, GitHub
Why Useful: Security wordlists, payloads, patterns, useful for domain vocabulary

Name: ArXiv cs.CR
Category: Research Corpus
URL: https://arxiv.org/list/cs.CR/recent
Size: 20,000+ papers
Format: PDF / XML
Access: Free, arxiv Python library or OAI-PMH API
Why Useful: Latest cybersecurity research papers, high quality technical text

Name: Semantic Scholar
Category: Research Corpus
URL: https://api.semanticscholar.org/
Size: Millions of papers, large cybersecurity subset
Format: JSON
Access: Free API key required
Why Useful: Paper abstracts, citations, and full text for cybersecurity research

Name: USENIX Security Proceedings
Category: Research Corpus
URL: https://www.usenix.org/publications/proceedings
Size: 1000+ papers
Format: PDF
Access: Free, open access
Why Useful: Top tier security conference papers, high quality domain text

Name: Security Stack Exchange
Category: Community / Web
URL: https://security.stackexchange.com/
Size: 100,000+ Q&A threads
Format: XML dump / API
Access: Free, data dump available at archive.org
Why Useful: Real world security questions and expert answers, great for Q&A style training

Name: GitHub Security Repositories
Category: Code / Community
URL: https://github.com/topics/cybersecurity
Size: Thousands of repos
Format: Text / Markdown / Code
Access: Free, GitHub API key required
Why Useful: Security tools, writeups, READMEs, and documentation with rich domain text

Name: Common Crawl
Category: Web Crawl
URL: https://commoncrawl.org/
Size: Petabytes, cybersecurity subset extractable
Format: WARC / WET
Access: Free, S3 access via boto3
Why Useful: Massive scale web text, security blogs and articles extractable with filtering