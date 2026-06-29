# Source Evaluation

1. NVD
License: Public Domain (US Government)
Status: Green
Quality: 5
Domain Coverage: 4
Extraction Difficulty: 2
Scalability: 5

2. MITRE ATT&CK
License: Apache 2.0
Status: Green
Quality: 5
Domain Coverage: 5
Extraction Difficulty: 2
Scalability: 4

3. AlienVault OTX
License: Open, free for non-commercial use
Status: Yellow
Quality: 4
Domain Coverage: 5
Extraction Difficulty: 2
Scalability: 5

4. Abuse.ch
License: Non-commercial use only
Status: Yellow
Quality: 3
Domain Coverage: 3
Extraction Difficulty: 1
Scalability: 4

5. CIRCL CVE Search
License: Public Domain
Status: Green
Quality: 4
Domain Coverage: 3
Extraction Difficulty: 1
Scalability: 5

6. VirusTotal
License: Free tier, non-commercial
Status: Yellow
Quality: 4
Domain Coverage: 4
Extraction Difficulty: 3
Scalability: 3

7. Shodan
License: Free tier, non-commercial
Status: Yellow
Quality: 3
Domain Coverage: 3
Extraction Difficulty: 3
Scalability: 3

8. MITRE CWE
License: Public Domain
Status: Green
Quality: 5
Domain Coverage: 4
Extraction Difficulty: 1
Scalability: 3

9. HuggingFace Cybersecurity Datasets
License: Varies per dataset
Status: Yellow
Quality: 4
Domain Coverage: 4
Extraction Difficulty: 1
Scalability: 4

10. Kaggle Cybersecurity Datasets
License: Varies per dataset
Status: Yellow
Quality: 3
Domain Coverage: 3
Extraction Difficulty: 2
Scalability: 3

11. SecLists
License: MIT
Status: Green
Quality: 3
Domain Coverage: 2
Extraction Difficulty: 1
Scalability: 2

12. ArXiv cs.CR
License: Open access, author retained
Status: Green
Quality: 5
Domain Coverage: 5
Extraction Difficulty: 2
Scalability: 5

13. Semantic Scholar
License: Open Research Corpus license
Status: Green
Quality: 5
Domain Coverage: 5
Extraction Difficulty: 2
Scalability: 5

14. USENIX Security
License: Open access
Status: Green
Quality: 5
Domain Coverage: 4
Extraction Difficulty: 3
Scalability: 3

15. Security Stack Exchange
License: CC BY-SA 4.0
Status: Green
Quality: 4
Domain Coverage: 4
Extraction Difficulty: 2
Scalability: 4

16. GitHub Security Repositories
License: Varies per repo
Status: Yellow
Quality: 3
Domain Coverage: 4
Extraction Difficulty: 3
Scalability: 5

17. Common Crawl
License: Open, no restrictions
Status: Green
Quality: 3
Domain Coverage: 3
Extraction Difficulty: 4
Scalability: 5

18. Exploit-DB
License: Public Domain
Status: Green
Quality: 5
Domain Coverage: 4
Extraction Difficulty: 2
Scalability: 4




Selected:

1.  ArXiv cs.CR          - Score 13 - Green
2.  Semantic Scholar     - Score 13 - Green
3.  NVD                  - Score 12 - Green
4.  MITRE ATT&CK         - Score 12 - Green
5.  AlienVault OTX       - Score 12 - Yellow
6.  CIRCL CVE Search     - Score 11 - Green
7.  MITRE CWE            - Score 11 - Green
8.  HuggingFace Datasets - Score 11 - Yellow
9.  Exploit-DB           - Score 11 - Green
10. Security Stack Exchange - Score 10 - Green
11. USENIX Security      - Score 9  - Green
12. Abuse.ch             - Score 9  - Yellow


Removed:

13. VirusTotal - Score 7 - Yellow
Reason: Low scalability on free tier, non-commercial restriction
14. GitHub Security Repos - Score 9 - Yellow
Reason: Inconsistent quality, license varies per repo, hard to extract cleanly
15. Kaggle Datasets - Score 7 - Yellow
Reason: Low quality score, inconsistent licenses, narrow coverage
16. Shodan - Score 6 - Yellow
Reason: Low quality text for training, non-commercial restriction, low scalability
17. SecLists - Score 6 - Green
Reason: Low domain coverage and scalability, more useful as a vocab reference than training data
18. Common Crawl - Score 7 - Green
Reason: High extraction difficulty, noisy text, needs heavy filtering to be useful