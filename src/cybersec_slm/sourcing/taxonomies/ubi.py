#!/usr/bin/env python3
"""The ``ubi`` profile: Indian banking regulatory-compliance taxonomy.

Four sub-domains: Compliance and Risk Management, AML-KYC, Internal Audit, and
Corporate Governance.

The AML/KYC track is spelled ``AML-KYC``, without the slash. A Sub-Domain name is
used verbatim as a directory component (``data/raw/<Sub-Domain>/<source>/``, see
``ingestion.worker``), so a ``/`` would split it into two levels and the cleaning
stage would then read the domain as "AML" and the source as "KYC".
``normalize.schema.DOMAIN_ALIASES`` maps the ``AML/KYC`` spelling onto this one,
so the label people actually type still resolves.

Legal scope. The pipeline builds a corpus for *commercial* training, so a source
is usable only when its license permits unencumbered commercial reuse, **or** it
is content we own. The keywords here draw on three pools:

  1. **Our own site** (``OWN_CONTENT_HOST``) — UBI's published policies and
     disclosures, authorized by the project owner. First-party, so no third-party
     licence is in play.
  2. **Statutory primary text** — Acts and Gazette-notified Rules via
     indiacode.nic.in / egazette.gov.in, under Copyright Act s.52(1)(q).
  3. **Open data and permissively-licensed datasets** — GODL-India on data.gov.in,
     plus HuggingFace / GitHub / Kaggle / Zenodo, resolved per artifact.

They deliberately avoid ``site:`` dorks against *third-party* regulator portals
(rbi.org.in, sebi.gov.in, fiuindia.gov.in), whose content is All-Rights-Reserved:
those only surface rows that ``ingestion.license_gate`` blocks anyway. RBI is
tracked instead as a metadata-only update feed, which raises no reproduction
question — see :mod:`cybersec_slm.sourcing.regfeed`.

See ``docs/sources/legal_scope.md`` for the evidence behind each entry in
``restricted_hosts``, and for the authorization behind ``OWN_CONTENT_HOST``.
"""

from __future__ import annotations

from . import OWNED_LICENSE, Taxonomy

# Union Bank of India's own site. First-party content: authorized for this corpus
# by the project owner on 2026-07-16 (recorded in docs/sources/legal_scope.md).
# This is an *authorization*, not a public licence — it is UBI's material to use.
# Kept as a constant because it is also the site: scope for the own-content
# keywords below, so the two cannot drift apart.
OWN_CONTENT_HOST = "unionbankofindia.bank.in"


# Our own content is reached by *crawling our own site* (see _SEED_ROWS), not by
# asking a search engine to enumerate it with `site:` dorks. That was the first
# approach and it does not work: every general web engine that honours `site:`
# rate-limits or CAPTCHAs a sweep within a few queries (duckduckgo "access
# denied", google/brave "too many requests", startpage/qwant CAPTCHA), and the
# API-based engines this pipeline targets ignore the operator outright. Crawling
# is also simply the right tool here — unionbankofindia.bank.in/robots.txt is
# `Allow: /` and publishes a sitemap, and it is our own site regardless.


_DATASETS: dict[str, list[str]] = {
    "Compliance and Risk Management": [
        "credit risk dataset",
        "operational risk loss event dataset",
        "market risk value at risk dataset",
        "Basel III capital adequacy dataset",
        "bank capital ratio dataset",
        "banking regulation text dataset huggingface",
        "regulatory compliance NLP dataset",
        "regtech compliance dataset github",
        "financial risk management dataset github",
        "credit default prediction dataset",
        "loan default dataset",
        "stress testing scenario dataset banking",
        "banking statistics India open data",
        "Banking Regulation Act 1949 indiacode",
        "Reserve Bank of India Act 1934 indiacode",
        "financial regulatory filings corpus",
    ],
    "AML-KYC": [
        "anti money laundering dataset",
        "AML transaction monitoring dataset",
        "money laundering detection dataset github",
        "suspicious transaction detection dataset",
        "financial crime dataset huggingface",
        "synthetic AML transaction dataset",
        "AMLSim synthetic money laundering dataset",
        "know your customer dataset",
        "customer due diligence dataset",
        "sanctions screening list dataset",
        "beneficial ownership register dataset",
        "politically exposed persons dataset",
        "financial fraud detection dataset",
        "entity resolution sanctions dataset",
        "Prevention of Money Laundering Act 2002 indiacode",
        "PMLA Maintenance of Records Rules 2005 gazette",
    ],
    "Internal Audit": [
        "internal audit dataset",
        "audit findings dataset",
        "risk based internal audit dataset",
        "audit report text dataset huggingface",
        "continuous auditing dataset github",
        "internal control testing dataset",
        "audit sampling dataset",
        "financial statement audit dataset",
        "audit workpaper corpus",
        "control deficiency dataset",
        "process mining audit event log dataset",
        "audit analytics dataset github",
    ],
    "Corporate Governance": [
        "corporate governance dataset",
        "board composition dataset",
        "board of directors dataset github",
        "corporate disclosure dataset huggingface",
        "related party transaction dataset",
        "ESG governance dataset",
        "executive compensation dataset",
        "insider trading dataset",
        "shareholding pattern dataset India open data",
        "annual report corpus dataset",
        "Companies Act 2013 indiacode",
        "corporate ownership structure dataset",
    ],
}

_TEXT: dict[str, list[str]] = {
    "Compliance and Risk Management": [
        "Basel III capital framework explained",
        "operational risk management banking explained",
        "credit risk management explained",
        "market risk management explained",
        "internal capital adequacy assessment process explained",
        "bank stress testing methodology explained",
        "non performing asset classification explained",
        "risk based supervision explained",
        "compliance function in banks explained",
        "regulatory reporting explained",
    ],
    "AML-KYC": [
        "customer due diligence explained",
        "know your customer process explained",
        "money laundering typologies explained",
        "beneficial ownership identification explained",
        "sanctions screening explained",
        "transaction monitoring rules explained",
        "politically exposed persons explained",
        "risk based approach anti money laundering explained",
        "trade based money laundering explained",
        "correspondent banking risk explained",
    ],
    "Internal Audit": [
        "risk based internal audit explained",
        "internal audit framework explained",
        "concurrent audit banking explained",
        "internal control over financial reporting explained",
        "audit sampling methodology explained",
        "three lines of defence model explained",
        "audit evidence and documentation explained",
        "internal audit charter explained",
        "audit planning methodology explained",
    ],
    "Corporate Governance": [
        "corporate governance principles explained",
        "board committee structure explained",
        "related party transactions explained",
        "insider trading regulation explained",
        "director duties and responsibilities explained",
        "board evaluation process explained",
        "audit committee role explained",
        "shareholder rights explained",
        "corporate disclosure obligations explained",
    ],
}

_VOCAB: dict[str, set[str]] = {
    "Compliance and Risk Management": {
        "compliance", "risk management", "basel", "capital adequacy",
        "credit risk", "operational risk", "market risk", "stress testing",
        "prudential", "npa", "provisioning", "regulatory reporting"},
    "AML-KYC": {
        "aml", "kyc", "money laundering", "due diligence", "sanctions",
        "beneficial ownership", "politically exposed", "suspicious transaction",
        "cdd", "financial crime", "pmla", "terrorist financing"},
    "Internal Audit": {
        "internal audit", "audit finding", "rbia", "concurrent audit",
        "internal control", "audit evidence", "three lines of defence",
        "control deficiency", "audit sampling", "workpaper"},
    "Corporate Governance": {
        "corporate governance", "board of directors", "related party",
        "insider trading", "disclosure", "shareholder", "board committee",
        "director", "annual report", "companies act"},
}

_CODES: dict[str, str] = {
    "AML-KYC": "AML_KYC",
    "Compliance and Risk Management": "COMPLIANCE_RISK",
    "Corporate Governance": "CORP_GOVERNANCE",
    "Internal Audit": "INTERNAL_AUDIT",
}

# Hosts whose content is *substantively on-topic* but cannot enter a commercial
# training corpus on the terms they publish. Discovery drops these up front (see
# ``sourcing.quality.passes``) rather than spending an enrichment fetch on a row
# the license gate would block later anyway.
#
# This is a licensing judgement, not a claim the content is unavailable: every one
# of these is free to *read*. What is absent is a grant to reproduce and train on
# commercially. Verified July 2026 against each site's published terms; re-check
# before relying on it, and get counsel's sign-off before moving anything out.
_RESTRICTED_HOSTS: dict[str, str] = {
    # "© Reserve Bank of India. All Rights Reserved." No reproduction grant; the
    # site disclaimer requires written permission even to deep-link, and
    # rbi.org.in/robots.txt answers automated clients with HTTP 418.
    "rbi.org.in": "all-rights-reserved; no reproduction grant; bot-hostile (418)",
    # No published reuse grant on these portals -> default-deny.
    "sebi.gov.in": "no published reuse grant; default-deny",
    "fiuindia.gov.in": "no published reuse grant; default-deny",
    "mca.gov.in": "no published reuse grant; default-deny (Acts: use indiacode.nic.in)",
    "cag.gov.in": "no published reuse grant; default-deny",
    # FATF/OECD asserts copyright over its reports and typologies.
    "fatf-gafi.org": "FATF/OECD copyright; reuse requires permission",
    # Standards bodies: copyrighted, largely paywalled.
    "icsi.edu": "ICSI copyright (Secretarial Standards); paywalled",
    "isaca.org": "ISACA copyright; paywalled",
    "theiia.org": "IIA copyright; paywalled",
    "bis.org": "BIS grants brief-excerpt reuse only, not full-text training",
    # Other banks' content: third-party, all rights reserved. (Union Bank's own
    # site is *not* here — it is first-party and authorized; see _OWN_CONTENT_HOSTS.)
    "sbi.co.in": "bank-owned content; all rights reserved",
    "pnbindia.in": "bank-owned content; all rights reserved",
    "bankofbaroda.in": "bank-owned content; all rights reserved",
    "canarabank.com": "bank-owned content; all rights reserved",
}

def _seed(name: str, sub_domain: str, url: str, description: str) -> dict:
    """One first-party crawl row for the catalog (kind=website via Category/Format)."""
    return {
        "Name": name,
        "Sub-Domain": sub_domain,
        "Description": description,
        "Dataset Link": url,
        "Category": "Website",
        "Original Format": "HTML",
        "License": OWNED_LICENSE,
        "Verified?": "Yes",
        "Note": "First-party content, owner-authorized 2026-07-16; "
                "see docs/sources/legal_scope.md",
    }


# Union Bank's own published policies and disclosures, seeded straight into the
# catalog so they need no discovery at all. These are the department's stated
# priority sources (Basel III, Risk Management Policy, AML, KYC, statutory branch
# auditors, audit & inspection, secretarial compliance, code of corporate
# governance) — each hub page below is crawled for the PDFs beneath it.
_SEED_ROWS: tuple[dict, ...] = (
    _seed("UBI Regulatory Disclosures", "Compliance and Risk Management",
          f"https://www.{OWN_CONTENT_HOST}/en/common/regulatory-disclosures",
          "Basel III Pillar 3 disclosures and regulatory filings (own content)"),
    _seed("UBI Policies", "Compliance and Risk Management",
          f"https://www.{OWN_CONTENT_HOST}/en/common/policies",
          "Published bank policies incl. Risk Management Policy (own content)"),
    _seed("UBI Policies (AML/KYC)", "AML-KYC",
          f"https://www.{OWN_CONTENT_HOST}/en/common/policies",
          "Published AML and KYC policy documents (own content)"),
    _seed("UBI Investor Relations", "Corporate Governance",
          f"https://www.{OWN_CONTENT_HOST}/en/common/investor-relations",
          "Annual reports, Code of Corporate Governance, secretarial compliance "
          "reports (own content)"),
)

TAXONOMY = Taxonomy(
    domain_name="BANKING_COMPLIANCE",
    datasets=_DATASETS,
    text=_TEXT,
    vocab=_VOCAB,
    codes=_CODES,
    # Why these specific hosts:
    #   * huggingface.co / github.com / gitlab.com / kaggle.com / zenodo.org --
    #     per-artifact licenses the deep detector can resolve (many MIT/Apache/CC0).
    #   * data.gov.in -- the Government of India OGD platform. Its contents carry
    #     GODL-India, which grants commercial reuse with attribution.
    #   * indiacode.nic.in / egazette.gov.in -- primary statutory text (Acts,
    #     Rules, Gazette notifications) carrying a Copyright Act s.52(1)(q)
    #     exemption.
    #   * arxiv.org -- open-access papers (per-paper license; often CC-BY).
    site_scope_hosts=(
        "huggingface.co", "github.com", "gitlab.com", "kaggle.com", "zenodo.org",
        "data.gov.in", "indiacode.nic.in", "egazette.gov.in", "arxiv.org",
        OWN_CONTENT_HOST,
    ),
    dataset_engines=("github", "openairedatasets", "arxiv", "semantic scholar"),
    # Deliberately omits Wikipedia: it is CC-BY-SA, and share-alike is a deny
    # pattern at the license gate, so indexing it would only manufacture rows that
    # get blocked. Stack Overflow (used by the cybersec profile) is dropped as
    # off-topic for banking regulation.
    text_engines=("github", "arxiv", "semantic scholar", "openairedatasets"),
    query_qualifier="dataset OR github OR repository OR corpus",
    text_query_qualifier="guide OR explained OR documentation OR handbook OR paper",
    # Only a general web engine honours ``site:``. Kept for any future dork, but
    # note these are unreliable for a sweep (see the note on _own above) — prefer a
    # seed row for a host we already know about.
    site_engines=("duckduckgo", "bing"),
    owned_hosts=(OWN_CONTENT_HOST,),
    seed_rows=_SEED_ROWS,
    restricted_hosts=_RESTRICTED_HOSTS,
)
