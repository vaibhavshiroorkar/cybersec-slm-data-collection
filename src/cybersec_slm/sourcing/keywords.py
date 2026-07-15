#!/usr/bin/env python3
"""Per-Sub-Domain search keywords and snippet-classification vocabulary."""

from __future__ import annotations

# Qualifiers appended to every query to bias results toward the kind of page the
# mode wants: structured corpora for ``datasets``, readable prose for ``text``.
QUERY_QUALIFIER = "dataset OR github OR repository OR corpus"
TEXT_QUERY_QUALIFIER = "guide OR tutorial OR explained OR documentation OR writeup"

# Licensable dataset / repo / paper hosts a ``datasets``-mode query is scoped to
# (via a SearXNG ``site:`` clause) so discovery leans toward sources whose license
# can actually be resolved. Text-mode queries are never scoped (prose comes from
# anywhere). The scope is a soft bias: a scoped query that returns nothing is
# retried unscoped by the discovery driver, so recall is never lost.
SITE_SCOPE_HOSTS: tuple[str, ...] = (
    "huggingface.co", "github.com", "gitlab.com", "kaggle.com", "zenodo.org",
    "arxiv.org", "data.gov", "archive.ics.uci.edu",
)


def site_clause(hosts: tuple[str, ...] = SITE_SCOPE_HOSTS) -> str:
    """A ``(site:a OR site:b ...)`` clause biasing a query toward licensable hosts."""
    return "(" + " OR ".join(f"site:{h}" for h in hosts) + ")"


# Reliable SearXNG engines the pipeline targets instead of the general web
# engines, which are perpetually rate-limited (brave/google "too many requests",
# duckduckgo "access denied", startpage "CAPTCHA"). These API-based engines index
# licensable sources directly and are not throttled. GitHub is listed first
# because it is by far the highest commercial-valid yield (MIT/Apache/BSD repos);
# the dataset/paper engines add reach (OpenAIRE carries CC-licensed datasets;
# arXiv/Scholar paginate deeply but mostly resolve to unknown at the license gate).
# Because these engines ignore ``site:`` operators, the site-scope clause above is
# not applied when they are in use.
DATASET_ENGINES: tuple[str, ...] = (
    "github", "openairedatasets", "arxiv", "semantic scholar",
)
# Prose/how-to sources. The general web engines that used to serve these are dead,
# so this stays thin (developer Q&A + docs-bearing repos + papers).
TEXT_ENGINES: tuple[str, ...] = (
    "github", "stackoverflow", "arxiv", "semantic scholar",
)


def default_engines(is_datasets: bool = True) -> str:
    """Comma-separated default engine list for a keyword set (datasets vs text)."""
    return ",".join(DATASET_ENGINES if is_datasets else TEXT_ENGINES)

DOMAIN_KEYWORDS: dict[str, list[str]] = {
    "Application Security": [
        "vulnerable source code dataset",
        "secure code review dataset",
        "SAST static analysis labeled dataset",
        "OWASP code vulnerability dataset",
        "CWE annotated source code dataset",
        "software vulnerability commit dataset",
        "web application attack payload dataset",
        "code security bug dataset github",
        "vulnerability detection machine learning dataset",
        "Devign vulnerability dataset",
        "Juliet test suite CWE dataset",
        "smart contract vulnerability dataset",
        "fuzzing corpus github",
        "SQL injection payload dataset",
        "software supply chain security dataset",
        "awesome application security",
    ],
    "Network Security": [
        "network intrusion detection dataset",
        "network traffic pcap labeled dataset",
        "IDS flow dataset cybersecurity",
        "DDoS attack network dataset",
        "botnet traffic dataset",
        "NetFlow anomaly detection dataset",
        "packet capture malware traffic dataset",
        "firewall log dataset",
        "CICIDS intrusion detection dataset",
        "UNSW-NB15 network dataset",
        "network anomaly detection github",
        "Zeek Suricata logs dataset",
        "malware traffic analysis dataset",
        "IoT network attack dataset",
        "awesome network security",
    ],
    "Cloud Security": [
        "cloud security misconfiguration dataset",
        "kubernetes security dataset",
        "cloud CSPM findings dataset",
        "AWS Azure GCP security best practices dataset",
        "container image vulnerability dataset",
        "cloud audit log dataset security",
        "terraform IaC misconfiguration dataset",
        "S3 bucket exposure dataset",
        "kubernetes audit logs dataset",
        "cloudtrail logs dataset",
        "falco runtime security rules github",
        "IaC security scanning dataset",
        "cloud attack detection dataset",
        "serverless security dataset",
        "awesome cloud security",
    ],
    "Identity Access and Management": [
        "identity access management dataset",
        "authentication logs dataset security",
        "privileged access abuse dataset",
        "IAM policy misconfiguration dataset",
        "account takeover dataset",
        "OAuth SAML token dataset",
        "insider threat access dataset",
        "RBAC permissions dataset",
        "authentication anomaly detection dataset",
        "login logs dataset github",
        "user behavior analytics dataset security",
        "access control policy dataset",
        "SSO federation dataset",
        "credential stuffing dataset",
        "awesome iam security",
    ],
    "Incident Response and Forensics": [
        "digital forensics dataset",
        "incident response playbook dataset",
        "memory forensics dataset",
        "DFIR investigation dataset",
        "disk image forensic dataset",
        "Windows event log forensic dataset",
        "timeline analysis artifact dataset",
        "malware incident case dataset",
        "volatility memory samples dataset",
        "windows forensic artifacts dataset",
        "log2timeline plaso dataset",
        "ransomware incident dataset github",
        "sysmon event dataset",
        "host intrusion detection dataset",
        "awesome incident response",
    ],
    "Data Security and Privacy": [
        "PII detection dataset",
        "data loss prevention dataset",
        "data privacy compliance dataset",
        "sensitive data classification dataset",
        "GDPR data subject dataset",
        "de-identification anonymization dataset",
        "data breach records dataset",
        "credential leak dataset",
        "named entity PII dataset",
        "text anonymization benchmark dataset",
        "differential privacy dataset",
        "synthetic PII dataset github",
        "sensitive data detection github",
        "data masking dataset",
        "awesome data privacy",
    ],
    "Penetration Testing": [
        "penetration testing dataset",
        "exploit proof of concept dataset",
        "exploit database github",
        "red team TTP dataset",
        "web pentest report dataset",
        "privilege escalation technique dataset",
        "attack payload dataset",
        "CTF exploit writeup dataset",
        "nuclei templates github",
        "metasploit modules github",
        "web attack payloads github",
        "OSCP privilege escalation writeup",
        "web application pentest dataset",
        "bug bounty writeups github",
        "awesome pentest",
    ],
    "Vulnerability Management": [
        "CVE vulnerability dataset",
        "CVSS scoring dataset",
        "vulnerability scan results dataset",
        "CWE weakness enumeration dataset",
        "patch management dataset",
        "vulnerability disclosure dataset",
        "NVD CVE feed dataset",
        "software vulnerability advisory dataset",
        "CVE json feed github",
        "exploit prediction EPSS dataset",
        "dependency vulnerability dataset",
        "OSV vulnerability database github",
        "security advisories dataset",
        "vulnerability scanner results dataset",
        "awesome vulnerability management",
    ],
    "Governance, Risk and Compliance": [
        "security compliance controls dataset",
        "GRC risk register dataset",
        "NIST CSF mapping dataset",
        "ISO 27001 controls dataset",
        "security policy document dataset",
        "audit findings dataset cybersecurity",
        "control framework mapping dataset",
        "regulatory compliance dataset security",
        "OSCAL security controls github",
        "CIS benchmark dataset",
        "security controls catalog dataset",
        "compliance mapping github",
        "risk assessment dataset github",
        "NIST 800-53 controls dataset",
        "awesome grc",
    ],
    "Cryptography": [
        "cryptography dataset",
        "cipher cryptanalysis dataset",
        "TLS certificate dataset security",
        "encryption algorithms labeled dataset",
        "side channel attack dataset",
        "post-quantum cryptography dataset",
        "NIST PQC standard dataset",
        "lattice-based cryptography dataset",
        "key exchange protocol dataset",
        "crypto CTF challenge dataset",
        "cryptographic protocol dataset",
        "TLS handshake dataset",
        "hash function analysis dataset",
        "homomorphic encryption dataset",
        "awesome cryptography",
    ],
    "Security Operations": [
        "SOC alert triage dataset",
        "SIEM log dataset",
        "security operations detection rules dataset",
        "threat hunting dataset",
        "Sigma rules dataset",
        "security alert labeled dataset",
        "log anomaly detection dataset",
        "EDR telemetry dataset",
        "sigma rules github",
        "detection rules dataset github",
        "MITRE ATT&CK detection dataset",
        "SOC log dataset github",
        "security alerts labeled dataset",
        "detection engineering dataset",
        "awesome detection engineering",
    ],
    "Threat Intelligence": [
        "threat intelligence dataset",
        "IOC indicators of compromise dataset",
        "MITRE ATT&CK technique dataset",
        "phishing URL dataset",
        "APT report dataset",
        "malicious domain dataset",
        "malware family classification dataset",
        "YARA rules dataset",
        "malware API call sequence dataset",
        "threat actor TTP dataset",
        "CTI feed dataset",
        "malware samples dataset github",
        "phishing email dataset github",
        "threat intelligence feeds github",
        "ransomware samples dataset",
    ],
}

# Prose-oriented catalog (mode "text"): articles, docs, tutorials, writeups.
DOMAIN_TEXT_KEYWORDS: dict[str, list[str]] = {
    "Application Security": [
        "OWASP top 10 explained",
        "secure coding best practices",
        "SQL injection prevention guide",
        "cross-site scripting XSS walkthrough",
        "threat modeling tutorial",
        "application security testing guide",
        "API security best practices",
        "common web vulnerabilities explained",
    ],
    "Network Security": [
        "network intrusion detection explained",
        "firewall configuration best practices",
        "DDoS mitigation guide",
        "network segmentation tutorial",
        "packet analysis with wireshark guide",
        "zero trust network architecture explained",
        "VPN security best practices",
        "network protocol attacks explained",
    ],
    "Cloud Security": [
        "AWS security best practices guide",
        "kubernetes security hardening tutorial",
        "cloud misconfiguration explained",
        "cloud IAM least privilege guide",
        "container security best practices",
        "cloud incident response guide",
        "securing S3 buckets tutorial",
        "cloud security posture management explained",
    ],
    "Identity Access and Management": [
        "identity and access management explained",
        "multi-factor authentication guide",
        "OAuth 2.0 explained",
        "SAML single sign-on tutorial",
        "privileged access management best practices",
        "zero trust identity guide",
        "RBAC vs ABAC explained",
        "preventing account takeover guide",
    ],
    "Incident Response and Forensics": [
        "incident response process explained",
        "digital forensics tutorial",
        "memory forensics with volatility guide",
        "DFIR investigation walkthrough",
        "malware incident handling guide",
        "windows event log analysis tutorial",
        "forensic artifact analysis explained",
        "ransomware incident response playbook",
    ],
    "Data Security and Privacy": [
        "data protection best practices",
        "GDPR compliance guide",
        "preventing data loss guide",
        "PII handling best practices",
        "data encryption at rest explained",
        "data classification tutorial",
        "privacy by design explained",
        "responding to a data breach guide",
    ],
    "Penetration Testing": [
        "penetration testing methodology guide",
        "exploit development tutorial",
        "red team operations guide",
        "web application pentest walkthrough",
        "privilege escalation techniques explained",
        "bug bounty writeup",
        "post-exploitation techniques explained",
        "lateral movement techniques guide",
    ],
    "Vulnerability Management": [
        "vulnerability management process explained",
        "CVSS scoring explained",
        "CVE and CWE explained",
        "patch management best practices",
        "vulnerability disclosure process explained",
        "risk-based vulnerability prioritization guide",
        "vulnerability scanning tools compared",
        "remediation SLA best practices",
    ],
    "Governance, Risk and Compliance": [
        "cybersecurity risk management guide",
        "NIST cybersecurity framework explained",
        "ISO 27001 implementation guide",
        "security policy writing best practices",
        "governance risk compliance explained",
        "security audit checklist",
        "third party risk management guide",
        "compliance frameworks compared",
    ],
    "Cryptography": [
        "cryptography explained",
        "how TLS works explained",
        "public key cryptography tutorial",
        "AES encryption explained",
        "digital signatures explained",
        "post-quantum cryptography explained",
        "NIST post-quantum standards guide",
        "migrating to quantum-safe cryptography guide",
        "common cryptographic attacks explained",
        "key management best practices",
    ],
    "Security Operations": [
        "security operations center explained",
        "SIEM best practices guide",
        "threat hunting guide",
        "writing detection rules tutorial",
        "alert triage process explained",
        "MITRE ATT&CK for detection guide",
        "SOC analyst workflow explained",
        "incident escalation best practices",
    ],
    "Threat Intelligence": [
        "cyber threat intelligence explained",
        "MITRE ATT&CK explained",
        "indicators of compromise guide",
        "threat actor profiling explained",
        "phishing analysis writeup",
        "malware analysis tutorial",
        "reverse engineering malware tutorial",
        "YARA rule writing guide",
        "APT campaign analysis",
        "threat intelligence lifecycle explained",
        "OSINT for threat intelligence guide",
    ],
}

# Distinctive terms per domain, used only to break ties on ambiguous results.
DOMAIN_VOCAB: dict[str, set[str]] = {
    "Application Security": {"sast", "owasp", "code", "sql injection", "xss",
                             "vulnerable code", "appsec", "source code"},
    "Network Security": {"intrusion", "ids", "pcap", "netflow", "ddos",
                         "packet", "traffic", "firewall"},
    "Cloud Security": {"cloud", "kubernetes", "aws", "azure", "gcp", "cspm",
                       "container", "s3 bucket", "misconfiguration"},
    "Identity Access and Management": {"iam", "identity", "authentication",
                                       "oauth", "saml", "privileged", "rbac"},
    "Incident Response and Forensics": {"forensics", "incident response",
                                        "dfir", "memory dump", "triage",
                                        "investigation", "artifact"},
    "Data Security and Privacy": {"pii", "privacy", "dlp", "gdpr",
                                  "sensitive data", "anonymization"},
    "Penetration Testing": {
        "penetration", "pentest", "exploit", "proof of concept", "poc",
        "metasploit", "red team", "privilege escalation", "payload"},
    "Vulnerability Management": {
        "vulnerability management", "cve", "cvss", "cwe", "nvd",
        "patch", "scan", "remediation", "disclosure"},
    "Governance, Risk and Compliance": {"compliance", "grc", "nist", "iso 27001",
                                        "controls", "audit", "risk register",
                                        "policy"},
    "Cryptography": {"cryptography", "cipher", "cryptanalysis", "encryption",
                     "tls", "certificate", "hash", "rsa", "aes",
                     "post-quantum", "pqc", "lattice", "kyber", "dilithium",
                     "ml-kem", "quantum-safe", "quantum-resistant"},
    "Security Operations": {"soc", "siem", "alert", "detection rule", "sigma",
                            "threat hunting", "triage"},
    "Threat Intelligence": {"threat intelligence", "ioc", "indicator",
                            "mitre att&ck", "phishing", "apt", "campaign",
                            "malware", "ransomware", "trojan", "yara",
                            "malware family"},
}

# mode name -> (keyword catalog, query qualifier)
_KEYWORD_SETS = {
    "datasets": (DOMAIN_KEYWORDS, QUERY_QUALIFIER),
    "text": (DOMAIN_TEXT_KEYWORDS, TEXT_QUERY_QUALIFIER),
}
MODES: tuple[str, ...] = ("datasets", "text", "both")


def keyword_sets(mode: str = "datasets") -> list[tuple[dict[str, list[str]], str]]:
    if mode == "both":
        return [_KEYWORD_SETS["datasets"], _KEYWORD_SETS["text"]]
    if mode in _KEYWORD_SETS:
        return [_KEYWORD_SETS[mode]]
    raise ValueError(f"unknown mode {mode!r}; valid: {MODES}")


# Canonical Sub-Domain labels (shared by both catalogs), exposed for CLI validation.
DOMAINS: tuple[str, ...] = tuple(DOMAIN_KEYWORDS)

# The top-level ``domain_name`` schema label for this pipeline's default corpus.
DEFAULT_DOMAIN_NAME = "CYBERSEC"

# Enum codes for the 12 built-in sub-domains, copied 1:1 from the historical
# ``normalize.schema.CANONICAL_TO_SUBDOMAIN`` mapping (the downstream snorkel
# LabelModel contract these codes must not silently change for). Keyed by name,
# not position, so this stays correct regardless of any dict's insertion order.
DOMAIN_CODES: dict[str, str] = {
    "Application Security": "APPLICATION",
    "Cloud Security": "CLOUD",
    "Cryptography": "CRYPTOGRAPHY",
    "Data Security and Privacy": "DATA_PRIVACY",
    "Governance, Risk and Compliance": "GRC",
    "Identity Access and Management": "IAM",
    "Incident Response and Forensics": "INCIDENT_RESPONSE",
    "Network Security": "NETWORK",
    "Penetration Testing": "PENTEST",
    "Security Operations": "SECOPS",
    "Threat Intelligence": "THREAT_INTELLIGENCE",
    "Vulnerability Management": "VULN_MANAGEMENT",
}
