# Profiles

A **profile** is one corpus the pipeline can build. Two ship built in:

| Profile | `domain_name` | Sub-domains | Catalog |
|---|---|---|---|
| `cybersec` | `CYBERSEC` | the original 12 cybersecurity domains | 1020 curated sources |
| `ubi` | `BANKING_COMPLIANCE` | AML-KYC, Compliance and Risk Management, Corporate Governance, Internal Audit | empty — sourcing fills it |

`ubi` is the default. Switching profiles re-points **every** stage at once: the
taxonomy sourcing searches on, the catalog ingestion reads, the sub-domain enum the
schema validates against, and the saved per-stage settings.

## Using them

```bash
cybersec-slm profile list           # every profile; * marks the active one
cybersec-slm profile show           # the active one's taxonomy + catalog
cybersec-slm profile show cybersec  # a specific one
cybersec-slm profile use cybersec   # switch (persisted)
```

The dashboard has a matching switcher in the sidebar on every page. It is disabled
while a run is in flight — switching mid-run would finish the run against a
different corpus than it started with.

For a one-off run or a test, the env var wins without disturbing the saved choice:

```bash
CYBERSEC_SLM_PROFILE=cybersec cybersec-slm source --mode datasets
```

Resolution order: `$CYBERSEC_SLM_PROFILE` → `sources/active_profile` → `ubi`. A
pointer naming a profile that no longer exists falls back to the default rather than
breaking every stage's import.

## Layout

```
sources/
  active_profile                  # the persisted choice
  profiles/
    cybersec/
      keywords.yaml               # taxonomy: sub-domains, keywords, codes, vocab
      Sources.csv                 # the discovered-source catalog
      Blacklist.csv               # rows rejected for a confirmed-red licence
    ubi/
      keywords.yaml
      Sources.csv
      Blacklist.csv
```

Per-profile settings live namespaced inside `pipeline_settings.json`
(`{"profiles": {"ubi": {"ingest": {...}}}}`). A legacy flat file from before
profiles existed is read as the active profile's and re-nested on the next write.

## Making a new one

```bash
cybersec-slm profile create medtech --domain-name MEDTECH --use
```

The new profile starts with **no** sub-domains — deliberately, so it cannot silently
inherit the previous corpus's sub-domains and enum codes. Add them on the dashboard's
Sourcing page, or edit `sources/profiles/medtech/keywords.yaml`.

To make it a built-in instead (shipped defaults, no manual seeding), add a module to
`src/cybersec_slm/sourcing/taxonomies/` exposing a `TAXONOMY` and register it in that
package's `TAXONOMIES`.

## Two things to know before you edit a taxonomy

**Sub-domain names become directory names.** Ingestion writes to
`data/raw/<Sub-Domain>/<source>/` using the name verbatim, and cleaning walks that
tree back reading level 1 as the domain and level 2 as the source. A name containing
`/` would split into two levels and be silently mis-parsed — which is why the AML/KYC
track is spelled **`AML-KYC`**. `catalog.validate_subdomain_name` rejects unsafe
names at the point of entry, and `schema.DOMAIN_ALIASES` maps the `AML/KYC` spelling
onto the canonical one so the label people actually type still resolves.

**Enum codes are a contract.** `SUBDOMAIN_NAMES` is ordered alphabetically by
sub-domain name, and that order is the name↔index mapping any downstream snorkel
LabelModel keys on. Adding or renaming a sub-domain reshuffles those indices, so an
already-trained LabelModel has to be re-fit. Codes should not change while records
carrying them exist.

## The `ubi` profile's legal scope

`ubi` bars a set of on-topic hosts (rbi.org.in, sebi.gov.in, fiuindia.gov.in,
FATF, the standards bodies, bank-owned sites) whose published terms do not permit the
commercial reuse a training corpus needs. Discovery drops them up front rather than
accumulating rows the licence gate would block anyway.

This is load-bearing and evidence-backed — read
[`docs/sources/legal_scope.md`](sources/legal_scope.md) before changing
`_RESTRICTED_HOSTS`. The `cybersec` profile declares no restricted hosts and relies
on the licence gate alone.
