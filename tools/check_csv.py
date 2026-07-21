import pandas as pd
import sys

# Ensure stdout handles unicode characters
sys.stdout.reconfigure(encoding='utf-8')

df = pd.read_csv("sources/profiles/ubi/Sources.csv", encoding="utf-8")
print(f"Total rows in catalog: {len(df)}")

print("\n=== Sampling Original Rows (Rows 2-25) ===")
for idx, row in df.head(25).iterrows():
    print(f"Row {idx+2} | Name: {row.get('Name')}")
    print(f"  Sub-Domain: {row.get('Sub-Domain')} | Country: {row.get('Country')}")
    print(f"  Link: {row.get('Dataset Link')}")
    print(f"  License: {row.get('License')}\n")

print("\n=== Sampling Newly Sourced Rows (Row 26 onwards) ===")
# Let's print a sample from index 25 onwards (new rows)
for idx, row in df.iloc[25:].head(25).iterrows():
    print(f"Row {idx+2} | Name: {row.get('Name')}")
    print(f"  Sub-Domain: {row.get('Sub-Domain')} | Country: {row.get('Country')}")
    print(f"  Link: {row.get('Dataset Link')}")
    print(f"  License: {row.get('License')}\n")
