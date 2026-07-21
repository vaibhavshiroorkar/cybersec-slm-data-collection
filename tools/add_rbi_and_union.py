import csv
import os

CATALOG_PATH = r"C:\Users\vaibh\Documents\GitHub\data-collection\sources\profiles\ubi\Sources.csv"

new_seeds = [
    {
        "Name": "RBI Notifications Feed",
        "Sub-Domain": "Compliance and Risk Management",
        "Field": "Finance",
        "Country": "India",
        "Description": "Reserve Bank of India official notifications and circulars RSS feed.",
        "Dataset Link": "https://www.rbi.org.in/notifications_rss.xml",
        "Category": "Feed",
        "Original Format": "RSS",
        "License": "Metadata index (title/date/URL only; facts, not copyrightable) - owner-authorized 2026-07-17",
        "Verified?": "Yes",
        "Date Added": "19/07/2026",
        "Note": "RBI regulatory feed"
    },
    {
        "Name": "RBI Publications Feed",
        "Sub-Domain": "Compliance and Risk Management",
        "Field": "Finance",
        "Country": "India",
        "Description": "Reserve Bank of India official publications and reports RSS feed.",
        "Dataset Link": "https://www.rbi.org.in/Publication_rss.xml",
        "Category": "Feed",
        "Original Format": "RSS",
        "License": "Metadata index (title/date/URL only; facts, not copyrightable) - owner-authorized 2026-07-17",
        "Verified?": "Yes",
        "Date Added": "19/07/2026",
        "Note": "RBI regulatory feed"
    },
    {
        "Name": "RBI Press Releases Feed",
        "Sub-Domain": "AML-KYC",
        "Field": "Finance",
        "Country": "India",
        "Description": "Reserve Bank of India press releases and announcements RSS feed.",
        "Dataset Link": "https://www.rbi.org.in/pressreleases_rss.xml",
        "Category": "Feed",
        "Original Format": "RSS",
        "License": "Metadata index (title/date/URL only; facts, not copyrightable) - owner-authorized 2026-07-17",
        "Verified?": "Yes",
        "Date Added": "19/07/2026",
        "Note": "RBI regulatory feed"
    },
    {
        "Name": "UBI Regulatory Disclosures",
        "Sub-Domain": "Compliance and Risk Management",
        "Field": "Finance",
        "Country": "India",
        "Description": "Basel III Pillar 3 disclosures and regulatory filings (own content)",
        "Dataset Link": "https://www.unionbankofindia.bank.in/en/common/regulatory-disclosures",
        "Category": "Website",
        "Original Format": "HTML",
        "License": "First-party (owner-authorized)",
        "Verified?": "Yes",
        "Date Added": "19/07/2026",
        "Note": "UBI Regulatory Disclosures PDF index"
    },
    {
        "Name": "UBI Policies",
        "Sub-Domain": "Compliance and Risk Management",
        "Field": "Finance",
        "Country": "India",
        "Description": "Published bank policies incl. Risk Management Policy (own content)",
        "Dataset Link": "https://www.unionbankofindia.bank.in/en/common/policies",
        "Category": "Website",
        "Original Format": "HTML",
        "License": "First-party (owner-authorized)",
        "Verified?": "Yes",
        "Date Added": "19/07/2026",
        "Note": "UBI Policies PDF index"
    },
    {
        "Name": "UBI Policies (AML/KYC)",
        "Sub-Domain": "AML-KYC",
        "Field": "Finance",
        "Country": "India",
        "Description": "Published AML and KYC policy documents (own content)",
        "Dataset Link": "https://www.unionbankofindia.bank.in/en/common/policies",
        "Category": "Website",
        "Original Format": "HTML",
        "License": "First-party (owner-authorized)",
        "Verified?": "Yes",
        "Date Added": "19/07/2026",
        "Note": "UBI Policies PDF index"
    },
    {
        "Name": "UBI Investor Relations",
        "Sub-Domain": "Corporate Governance",
        "Field": "Finance",
        "Country": "India",
        "Description": "Annual reports, Code of Corporate Governance, secretarial compliance reports (own content)",
        "Dataset Link": "https://www.unionbankofindia.bank.in/en/common/investor-relations",
        "Category": "Website",
        "Original Format": "HTML",
        "License": "First-party (owner-authorized)",
        "Verified?": "Yes",
        "Date Added": "19/07/2026",
        "Note": "UBI Investor Relations PDF index"
    }
]

def main():
    existing_links = set()
    header = []
    if os.path.exists(CATALOG_PATH):
        with open(CATALOG_PATH, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)
            for row in reader:
                if len(row) > 5:
                    existing_links.add(row[5].strip().lower())
    
    appended = 0
    with open(CATALOG_PATH, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=header)
        for seed in new_seeds:
            link = seed["Dataset Link"].strip().lower()
            if link not in existing_links:
                full_row = {col: seed.get(col, "") for col in header}
                writer.writerow(full_row)
                existing_links.add(link)
                appended += 1
                print(f"Appended {seed['Name']} to catalog.")
    print(f"Done. Appended {appended} new seeds to catalog.")

if __name__ == "__main__":
    main()
