import httpx
import re

url = "https://www.unionbankofindia.bank.in/en/common/regulatory-disclosures"
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

r = httpx.get(url, headers=headers)
print("Status:", r.status_code)

links = re.findall(r'href=[\'"]([^\'"]+)[\'"]', r.text)
print("Total links found:", len(links))

pdf_links = [l for l in links if "pdf" in l.lower()]
print("PDF links count:", len(pdf_links))
print("First 15 PDF links:")
for l in pdf_links[:15]:
    print(" ", l)
