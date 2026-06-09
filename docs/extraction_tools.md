# Extraction Tools

## Scrapy
- Best for: crawling security blogs, static websites, writeup archives
- Limitation: does not handle JavaScript rendered pages

## Playwright
- Best for: sites that need JavaScript to load content
- Limitation: slower than Scrapy, heavier on resources

## HuggingFace datasets
- Best for: downloading ready-made datasets in one line
- Limitation: only works for what is already on HuggingFace

## requests
- Best for: calling APIs like NVD, MITRE ATT&CK, OTX
- Limitation: you handle pagination and rate limits manually

## wget / curl
- Best for: bulk downloading static files and dataset dumps
- Limitation: no logic, just downloads what you point it at

## Academic loaders (arxiv)
- Best for: pulling research papers from ArXiv
- Limitation: limited to what the API exposes