# Source Acceptance Criteria

## Licensing
- Allowed: Green (open license, training explicitly permitted)
- Conditional: Yellow (license ambiguous, needs case-by-case review)
- Rejected: Red (no training use, proprietary, paywalled)

## Content Quality
- Must contain full text, not just titles or metadata
- Must be in English (primary language for this corpus)
- Must be machine-readable (HTML, JSON, PDF, plain text)

## Minimum Size
- Web sources: at least 100 articles or pages
- Datasets: at least 1000 records
- APIs: must support bulk access or pagination

## Domain Relevance
A source must cover at least one of these nine categories:
1. Attacks (techniques, incidents, case studies)
2. Attack Prevention (controls, hardening, best practices)
3. Code (malware samples, security tools, PoC exploits)
4. Vulnerabilities (CVEs, advisories, disclosures)
5. Policies (NIST, ISO standards, frameworks)
6. Compliance Reports (audits, assessments, certifications)
7. Articles, News, Blogs (threat intelligence, commentary)
8. Scraping Techniques (data collection methodology)
9. Other Python Libraries (security-relevant tooling docs)

## Scalability
- Must be accessible programmatically (API, bulk download, or scrapeable without login)
- Must be maintainable and re-pullable in future pipeline runs
