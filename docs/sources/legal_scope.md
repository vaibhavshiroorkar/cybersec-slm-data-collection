# Legal scope of the `ubi` corpus

**Status:** engineering assessment, verified July 2026. **Not legal advice.** Union
Bank of India is a regulated entity with counsel; nothing here substitutes for their
sign-off, and the questions flagged as open in the last section need it before the
corpus is used for anything beyond internal experimentation.

## The constraint

The pipeline builds a corpus for **commercial** model training. That is reproduction
plus preparation of a derivative work — not reading, and not fair dealing. So a
source is usable only when its licence permits unencumbered commercial reuse.
`ingestion/license_gate.py` enforces this and is **default-deny**: a blank or
unrecognised licence is blocked, and copyleft / share-alike / non-commercial /
all-rights-reserved terms are blocked explicitly.

This is why the corpus cannot simply mirror the department's reading list. Most of
what a compliance officer reads daily — RBI Master Directions above all — is free to
*read* and not licensed to *train on*.

## Findings per source

| Source | Terms found | Verdict |
|---|---|---|
| `rbi.org.in` | "© Reserve Bank of India. **All Rights Reserved**". No reproduction grant on the copyright page or the disclaimer. The disclaimer requires prior written permission even to deep-link. `robots.txt` answers automated clients with **HTTP 418**. | **Full text barred.** `all rights reserved` is a deny pattern in `license_gate._DENY`, so a full-text row is blocked at ingestion even if discovered. The RSS feeds (`notifications_rss.xml`, `pressreleases_rss.xml`, `Publication_rss.xml`, `AnnualReportMain_rss.xml`, `speeches_rss.xml`) are ingested **metadata-only** — title, date and URL, no summary prose — under `rss.META_INDEX_LICENSE`. That is an index of facts, not a reproduction, which is the form this row always contemplated. `rss.scrape_rss(metadata_only=True)` enforces it by dropping the summary, so the licence label cannot outrun the record. Note `/Scripts/rss.aspx` is **not** a feed: it is an HTML page listing the real feed URLs above, and `rss.parse` refuses it. Owner-authorized 2026-07-17. |
| `sebi.gov.in` | No published reuse grant located. | **Barred** (default-deny). |
| `fiuindia.gov.in` | No published reuse grant located. | **Barred** (default-deny). |
| `mca.gov.in` | No published reuse grant located. MCA hosts the Companies Act, but the Act's *text* is exempt wherever it is obtained — take it from `indiacode.nic.in`. | **Barred** as a host; the statute is reachable elsewhere. |
| `fatf-gafi.org` | FATF/OECD asserts copyright over reports and typologies. | **Barred.** |
| `icsi.edu` (Secretarial Standards), `isaca.org`, `theiia.org` | Copyrighted, largely paywalled. | **Barred.** |
| `bis.org` (Basel framework) | BIS permits reproduction of **brief excerpts** with attribution — not full-text ingestion into a training corpus. | **Barred** for this use. |
| **`unionbankofindia.bank.in`** | Our own content. Not a licence question — it is UBI's material to use. | **Authorized by the project owner, 2026-07-16.** See "Own content" below. |
| Other bank sites (SBI, PNB, BoB, Canara) | Third-party bank content, all rights reserved. | **Barred.** |
| **`data.gov.in`** (OGD platform, incl. RBI data published there) | **GODL-India**: permits use, adaptation and derivative works "for all lawful commercial and non-commercial purposes", with attribution. | **Allowed**, attribution required. |
| **`indiacode.nic.in`**, **`egazette.gov.in`** | **Copyright Act 1957 s.52(1)(q)** — see the caveat below. | **Allowed**, with the s.52(1)(q)(ii) condition noted. |
| `huggingface.co`, `github.com`, `gitlab.com`, `kaggle.com`, `zenodo.org` | Per-artifact licences. | **Resolved per source** by the licence detector + gate. |
| `arxiv.org` | Per-paper licence; often CC-BY, sometimes non-commercial. | **Resolved per source.** |

The barred hosts are encoded in `sourcing/taxonomies/ubi.py::_RESTRICTED_HOSTS` with
their reason, and dropped at discovery by `sourcing/quality.py::reject_reason`, so
the pipeline never spends an enrichment fetch on a row the gate would reject.

## The s.52(1)(q) caveat — read this before relying on it

Section 52(1)(q) of the Copyright Act 1957 exempts reproduction of:

- **(i)** any matter published in the Official Gazette, *except* an Act of a
  Legislature;
- **(ii)** any Act of a Legislature, **"subject to the condition that such Act is
  reproduced or published together with any commentary thereon or any other original
  matter"**;
- **(iii)** reports of committees/commissions, unless reproduction is prohibited;
- **(iv)** judgments or orders of courts.

Two consequences the keyword lists rely on:

- **Gazette-notified Rules** (e.g. the PMLA Maintenance of Records Rules 2005) fall
  under **(i)** and are freely reproducible.
- **Acts themselves** (PMLA 2002, Companies Act 2013, Banking Regulation Act 1949)
  fall under **(ii)**, whose proviso requires accompanying commentary or other
  original matter. Whether a training corpus satisfies that proviso is **genuinely
  unsettled** and is one of the open questions below. The pipeline does not assume it
  does; these keywords are included because the statutory text is the highest-value,
  lowest-risk material available, but the proviso is a real condition, not a
  formality.

Note also that RBI Master Directions are issued by RBI under statutory powers and
published on rbi.org.in under RBI's own copyright. Some are notified in the Gazette;
where that is so, the *Gazette* version may carry the (i) exemption even though the
rbi.org.in rendering does not. That is a per-instrument question, not a blanket
permission, and is not something this pipeline resolves automatically.

## What this means for corpus size

The department's keyword list was built around `site:rbi.org.in` dorks. Those are the
single richest seam of on-topic Indian regulatory text, and they are the ones this
scope excludes. The `ubi` profile is therefore materially smaller than the
cybersecurity corpus was, and leans on:

1. statutory primary text (`indiacode.nic.in`, eGazette),
2. GODL-India open data (`data.gov.in`),
3. permissively-licensed AML / credit-risk / audit / governance datasets on
   HuggingFace, GitHub, Kaggle, Zenodo,
4. open-access research on the four subject areas.

If the corpus proves too thin, the lever is **licensing, not crawling**: see below.

## Own content (`unionbankofindia.bank.in`)

**Authorized by the project owner on 2026-07-16.** This is an *authorization*, not a
licence: UBI's published policies and disclosures are the bank's own material, so no
third-party grant is in play. Recorded here rather than inferred from the site, which
publishes no licence at all.

How it is wired, and why each piece:

- `sourcing/taxonomies/ubi.py::OWN_CONTENT_HOST` names the host; `owned_hosts`
  declares it as ours.
- Enrichment stamps those rows `First-party (owner-authorized)`
  (`taxonomies.OWNED_LICENSE`) instead of scraping a licence off the page. Without
  this they resolve to `unknown`, and the default-deny gate blocks them — the
  authorization would be silently inert.
- The stamp keys on the **host**, never on page text, so no third-party source can
  talk its way past the gate by printing the words "first-party".
- The documents are reached by **crawling** the hub pages seeded in `_SEED_ROWS`, not
  by `site:` search dorks. Two reasons: `robots.txt` on that host is `Allow: /` with a
  sitemap, so crawling is the intended route; and every search engine that honours
  `site:` (DuckDuckGo, Google, Brave, Startpage, Qwant) rate-limits or CAPTCHAs a
  sweep within a handful of queries, which made the dork approach fail in practice.

Scope of the authorization as recorded: published policies, Basel III / Pillar 3
disclosures, annual reports, code of corporate governance, and secretarial compliance
reports. It does not extend to anything behind authentication, customer data, or
internal-only material — the crawl only ever sees what the public site serves.

## Open questions for Legal

1. **RBI content.** Is there an existing arrangement, or can permission be sought,
   covering reproduction of RBI Directions for internal model training? RBI's terms
   contemplate written permission; nobody has asked.
2. **s.52(1)(q)(ii) proviso.** Does a training corpus containing statutory text count
   as reproducing it "together with commentary or other original matter"? This
   governs whether the Acts (as opposed to the Gazette Rules) are safely in scope.
3. **Attribution mechanics for GODL-India.** GODL requires a published attribution
   statement naming provider, source and licence. Where does that live for a model
   trained on the corpus — a model card, a NOTICE file, or the dataset release?

## Changing the scope

Do not edit `_RESTRICTED_HOSTS` casually — it is the mechanism keeping unlicensable
material out of a commercial corpus. To move a host out of it:

1. record the licence or permission that changed, with a date and a link, in this
   file;
2. get counsel's sign-off for anything regulator- or bank-owned;
3. remove the entry and re-run discovery.

The licence gate remains the backstop either way: a host leaving `_RESTRICTED_HOSTS`
only means rows get *discovered*: each one still has to pass `license_gate` on its
own licence to be fetched.

