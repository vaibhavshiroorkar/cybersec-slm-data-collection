"""
prune_sources.py
================
Aggressively removes junk rows from Sources.csv that are NOT relevant to:
  - Indian Finance (primarily India, secondarily Global-finance)
  - 4 sub-domains: AML-KYC, Compliance and Risk Management,
                   Internal Audit, Corporate Governance

Strategy:
  1. KEEP rows from authoritative trusted sources always (rbi.org.in,
     sebi.gov.in, data.gov.in, huggingface.co, arxiv.org, bankwebsites…)
  2. For GitHub and other SearXNG-discovered rows: require at least one
     STRONG finance keyword in name+description+URL
  3. Remove rows where name/description contains clear off-topic signals
     (movie, airline, chaturbate, telecom, AWS, digital marketing, etc.)

Run:
    uv run --no-sync python prune_sources.py
"""

import csv
import re
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

CSV_PATH = Path("sources/profiles/ubi/Sources.csv")

# ---------------------------------------------------------------------------
# ALWAYS-KEEP hosts — authoritative finance/gov sources
# ---------------------------------------------------------------------------
ALWAYS_KEEP_HOSTS = {
    "rbi.org.in",
    "sebi.gov.in",
    "fiuindia.gov.in",
    "mca.gov.in",
    "ibbi.gov.in",
    "npci.org.in",
    "irdai.gov.in",
    "enforcementdirectorate.gov.in",
    "drt.gov.in",
    "nclt.gov.in",
    "indiacode.nic.in",
    "egazette.gov.in",
    "data.gov.in",
    "fatf-gafi.org",
    "bis.org",
    "unionbankofindia.bank.in",
    # Indian bank domains
    "sbi.co.in", "onlinesbi.sbi",
    "hdfcbank.com",
    "icicibank.com",
    "axisbank.com",
    "pnbindia.in",
    "bankofbaroda.in",
    "canarabank.com",
    "nabard.org",
    "sidbi.in",
    "nhb.org.in",
    "eximbankindia.in",
    "idrbt.ac.in",
    "iba.org.in",
    # Indian bank .co.in / .in generated URLs (from pattern backend)
    "uco-bank.co.in",
    "indian-bank.co.in",
    "indian-overseas-bank.co.in",
    "central-bank-india.co.in",
    "bank-of-maharashtra.co.in",
    "bank-of-india.co.in",
    "federal-bank.co.in",
    "south-indian-bank.co.in",
    "karnataka-bank.co.in",
    "karur-vysya-bank.co.in",
    "city-union-bank.co.in",
    "lakshmi-vilas-bank.co.in",
    "rbl-bank.co.in",
    "bandhan-bank.co.in",
    "idfc-first-bank.co.in",
    "kotak-mahindra-bank.co.in",
    "indusind-bank.co.in",
    "yes-bank.co.in",
    "jammu-kashmir-bank.co.in",
    "dhanlaxmi-bank.co.in",
    "au-small-finance-bank.co.in",
    "equitas-small-finance.co.in",
    "suryoday-small-finance-bank.co.in",
    "ujjivan-small-finance-bank.co.in",
    # NBFC patterns
    "bajaj-finance.com",
    "mahindra-finance.com",
    "shriram-finance.com",
    "muthoot-finance.com",
    "manappuram-finance.com",
    "aditya-birla-finance.com",
    "hdb-financial-services.com",
    "tata-capital-financial-services.com",
    "cholamandalam-investment-finance.com",
    "iifl-finance.com",
    "lic-housing-finance.com",
    "pnb-housing-finance.com",
    # Open data / research
    "arxiv.org",
    "zenodo.org",
    "kaggle.com",
    "huggingface.co",
    "github.com",           # github gets further filtering below
    "gitlab.com",
    "indiabudget.gov.in",
    "incometaxindia.gov.in",
    "gstcouncil.gov.in",
}

# ---------------------------------------------------------------------------
# STRONG finance signals — a row must contain at least one of these
# (for GitHub/HuggingFace rows that aren't from always-keep gov domains)
# ---------------------------------------------------------------------------
FINANCE_STRONG = {
    # Banking & regulation
    "bank", "banking", "banker",
    "rbi", "sebi", "irdai", "nbfc", "fiu",
    "reserve bank", "central bank",
    "basel", "pillar 3", "capital adequacy", "crar",
    "npa", "npa prediction", "non performing",
    "credit risk", "credit rating", "credit score",
    "loan", "lending", "borrower", "mortgage",
    "deposit", "savings account", "current account",
    "interest rate", "monetary policy",
    # AML/fraud
    "aml", "anti money laundering", "money laundering",
    "kyc", "know your customer",
    "fraud detection", "fraud", "fraudulent",
    "suspicious transaction", "str reporting",
    "pmla", "fema", "hawala",
    "sanctions", "beneficial owner", "pep", "politically exposed",
    "upi fraud", "payment fraud", "financial crime",
    # Compliance/risk
    "compliance", "regulatory", "regulation",
    "risk management", "operational risk", "market risk", "liquidity risk",
    "stress test", "irac", "provisioning",
    "audit", "internal audit", "concurrent audit",
    "governance", "corporate governance", "board",
    # Payments
    "upi", "npci", "rtgs", "neft", "imps", "bbps",
    "fintech", "payment gateway", "digital payment",
    # India finance specific
    "sebi order", "rbi circular", "rbi notification",
    "ibc", "insolvency", "sarfaesi", "drt",
    "priority sector", "mudra", "pmay",
    "gst fraud", "gst compliance",
    "income tax", "cbdt",
    "ipo", "mutual fund", "nse", "bse", "stock exchange",
    "nbfc regulation", "microfinance", "mfi",
    "treasury", "government securities", "g-sec",
    # Finance datasets
    "finance dataset", "financial dataset",
    "banking dataset", "transaction dataset",
    "credit dataset", "loan dataset",
    "stock market data", "equity data",
}

# ---------------------------------------------------------------------------
# HARD OFF-TOPIC patterns — immediate rejection even from github.com
# These are unambiguously non-finance
# ---------------------------------------------------------------------------
OFF_TOPIC_PATTERNS = [
    # Entertainment / consumer
    r"\bmovie\b", r"\bcinema\b", r"\bfilm\b",
    r"\bticket booking\b", r"\bairline\b", r"\bflight\b",
    r"\brestaurant\b", r"\bfood delivery\b", r"\brecipe\b",
    r"\bcooking\b", r"\bhotel\b",
    r"\bchaturbate\b", r"\badult\b",
    r"\bsoccer\b", r"\bsports\b", r"\bcricket score\b",
    r"\bmusic\b", r"\bspotify\b", r"\byoutube\b",
    r"\bgaming\b", r"\bgame\b", r"\brpg\b",
    r"\bnft\b", r"\bcryptopunk\b",
    # Marketing / SEO spam (very common SearXNG junk)
    r"\bdigital marketing\b", r"\bseo\b", r"\bsocial media marketing\b",
    r"\bcontent marketing\b", r"\baffiliate marketing\b",
    r"\bweb development\b", r"\bwebsite design\b",
    r"\bwordpress\b", r"\bshopify\b", r"\bwoocommerce\b",
    r"\bcraiglist\b", r"\bcraigslist\b",
    r"\bwhite label\b", r"\bapp development\b",
    r"\bmobile app\b", r"\bui ux\b", r"\bux design\b",
    # Infrastructure / CS coursework (not finance)
    r"\baws ec2\b", r"\bkubernetes\b", r"\bdocker\b",
    r"\bspring boot\b", r"\bjava assignment\b",
    r"\bcs61\b", r"\bcomp sci\b",
    r"\bchromium\b", r"\bbrowser extension\b",
    r"\blinux\b.*\btutorial\b",
    # Telecom (distinct from fintech)
    r"\btelecom churn\b", r"\btelecommunication\b",
    r"\bmobile network\b",
    # Medical / bio (common false positive)
    r"\bmedical imaging\b", r"\bchest x.ray\b",
    r"\bgenomics\b", r"\bclinical trial\b",
    r"\bcovid\b", r"\bpandemic\b", r"\bvaccin\b",
    # Other clearly off-topic
    r"\bweather forecast\b", r"\bclimate model\b",
    r"\belection\b.*\bvote\b", r"\bvoter\b",
    r"\bdrone\b.*\bswarm\b",
    r"\bcounterinsurgency\b", r"\bmilitary\b.*\boperation\b",
    r"\bbook recommendation\b",
    r"\breputation management\b",
    r"\bpancake\b",  # yes this was in there
    r"\brentalprice\b", r"\brental price prediction\b",
]

_OFF_TOPIC_RE = re.compile(
    "|".join(OFF_TOPIC_PATTERNS), re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_host(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.lower().removeprefix("www.")
    except Exception:
        return ""


def is_always_keep(host: str) -> bool:
    # Exact match or suffix match
    return any(
        host == h or host.endswith("." + h)
        for h in ALWAYS_KEEP_HOSTS
    )


def has_finance_signal(text: str) -> bool:
    text_l = text.lower()
    return any(kw in text_l for kw in FINANCE_STRONG)


def has_off_topic(text: str) -> bool:
    return bool(_OFF_TOPIC_RE.search(text))


def row_text(row: dict) -> str:
    name = row.get("Name") or ""
    desc = row.get("Description") or ""
    url = row.get("Dataset Link") or ""
    note = row.get("Note") or ""
    return f"{name} {desc} {url} {note}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"Reading {CSV_PATH}...")
    with open(CSV_PATH, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)
    print(f"  {len(rows):,} rows loaded.")

    kept = []
    removed = []
    reasons = Counter()

    for row in rows:
        url  = (row.get("Dataset Link") or "").strip()
        host = get_host(url)
        text = row_text(row)

        # ── Rule 1: Always-keep authoritative gov/bank/research hosts ──────
        if is_always_keep(host) and "github.com" not in host:
            kept.append(row)
            continue

        # ── Rule 2: Hard off-topic signal — remove regardless of host ──────
        if has_off_topic(text):
            removed.append((row, "off-topic pattern"))
            reasons["off-topic pattern"] += 1
            continue

        # ── Rule 3: GitHub / HuggingFace / unknown — must have finance KW ──
        if not has_finance_signal(text):
            removed.append((row, "no finance signal"))
            reasons["no finance signal"] += 1
            continue

        # ── Passed all gates ────────────────────────────────────────────────
        kept.append(row)

    print(f"\n  Kept   : {len(kept):,}")
    print(f"  Removed: {len(removed):,}")
    print("\nRemoval reasons:")
    for reason, cnt in reasons.most_common():
        print(f"  {reason}: {cnt:,}")

    # Show a sample of what's being removed
    print("\nSample of removed rows (first 30):")
    for row, reason in removed[:30]:
        name = (row.get("Name") or "")[:55]
        auth = (row.get("Author") or "")[:30]
        print(f"  [{reason}] {name} | {auth}")

    # Country / subdomain stats of kept rows
    print(f"\nKept rows stats:")
    countries = Counter(r.get("Country","") for r in kept)
    for k, v in countries.most_common():
        pct = v / len(kept) * 100
        print(f"  {k}: {v:,} ({pct:.1f}%)")

    sds = Counter(r.get("Sub-Domain","") for r in kept)
    print("\nSub-Domain (kept):")
    for k, v in sds.most_common():
        print(f"  {k}: {v:,}")

    print(f"\nWriting cleaned catalog ({len(kept):,} rows) to {CSV_PATH}...")
    with open(CSV_PATH, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(kept)
    print("Done.")

if __name__ == "__main__":
    main()
