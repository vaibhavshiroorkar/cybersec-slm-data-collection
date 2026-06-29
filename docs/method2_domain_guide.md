# Method 2 - Domain-Based Individual Stages Cleaning

## Overview
Use Method 2 (individual stages) to clean datasets with outputs organized by domain.

**Output structure:**
```
cleaned_data/
├── Security Operations/
│   ├── sanitize/           (encoding fixes, dates, fields)
│   ├── dedup/              (exact + near duplicates removed)
│   ├── pii/                (PII detected & redacted)
│   └── lang/               (non-English filtered out)
└── Threat Intelligence/
    ├── sanitize/
    ├── dedup/
    ├── pii/
    └── lang/
```

---

## Quick Start

### 1. List Available Domains
```bash
python tools/clean_by_domain.py list
```
Output:
```
Available domains (2):
  • Security Operations
  • Threat Intelligence
```

### 2. Clean All Domains (Full Run)
Run all stages through all domains sequentially:
```bash
python tools/clean_by_domain.py all
```

### 3. Clean Specific Domain
Run all stages for just one domain:
```bash
python tools/clean_by_domain.py all "Security Operations"
```

### 4. Test with Limit (Before Full Run)
Cap records per file for quick testing:
```bash
python tools/clean_by_domain.py all "Security Operations" --limit 20
```
(Process only 20 records per file)

### 5. Run Individual Stages

**Sanitize only (fix encoding, dates, missing fields):**
```bash
python tools/clean_by_domain.py sanitize
```

**Deduplication only:**
```bash
python tools/clean_by_domain.py dedup
```

**PII redaction only:**
```bash
python tools/clean_by_domain.py pii
```

**Language filtering only:**
```bash
python tools/clean_by_domain.py lang
```

---

## What Each Stage Does

| Stage | Description | Example |
|-------|-------------|---------|
| **sanitize** | Fix encoding, normalize dates, fill missing fields | `2023-1-5` → `2023-01-05` |
| **dedup** | Remove exact & near-duplicate records | Hash-based + MinHash LSH |
| **pii** | Detect & anonymize PII (email, SSN, phone, IP, CC) | `john@email.com` → `<EMAIL_ADDRESS>` |
| **lang** | Drop non-English, keep English only | French text → dropped |

---

## Use Cases

### For Investigation - Find Which Stage Drops Records
```bash
# 1. Run just sanitize
python tools/clean_by_domain.py sanitize "Threat Intelligence"

# 2. Check output
ls cleaned_data/"Threat Intelligence"/sanitize/
wc -l cleaned_data/"Threat Intelligence"/sanitize/*.jsonl

# 3. Compare with dedup
python tools/clean_by_domain.py dedup "Threat Intelligence"
ls cleaned_data/"Threat Intelligence"/dedup/
```

### For Production - Full Clean of Everything
```bash
python tools/clean_by_domain.py all
```
This runs:
1. Sanitize all domains
2. Dedup all domains  
3. PII redaction all domains
4. Language filter all domains

Output goes to `cleaned_data/<domain>/<stage>/`

### For Specific Domain Only
```bash
# Clean only Security Operations
python tools/clean_by_domain.py all "Security Operations"

# Check results
cat cleaned_data/"Security Operations"/sanitize/*.jsonl | wc -l
```

---

## Output Files

After running, check the outputs:

```powershell
# Count files created
Get-ChildItem cleaned_data -Recurse -File | Measure-Object

# View sanitized records from a specific domain
Get-ChildItem "cleaned_data/Security Operations/sanitize/" -Recurse -File

# View one file
Get-Content "cleaned_data/Security Operations/sanitize/sigma-rules.jsonl" -TotalCount 1 | ConvertFrom-Json | ConvertTo-Json
```

---

## Test Results (Example)

Running: `python tools/clean_by_domain.py all "Security Operations" --limit 20`

```
Input:  200 records (10 files × 20 limit)
After Sanitize:  200 kept (100%)
After Dedup:      99 kept (49.5% - many duplicates!)
After PII:        99 kept (no changes)
After Lang:       99 kept (100% English)
```

---

## Comparing Stages Side-by-Side

To understand what each stage does, compare outputs:

```bash
# Before sanitize
wc -l raw_data/Security\ Operations/*/sigma-rules.jsonl

# After sanitize
wc -l cleaned_data/"Security Operations"/sanitize/sigma-rules.jsonl

# After dedup
wc -l cleaned_data/"Security Operations"/dedup/sigma-rules.jsonl

# After PII
wc -l cleaned_data/"Security Operations"/pii/sigma-rules.jsonl

# After lang
wc -l cleaned_data/"Security Operations"/lang/sigma-rules.jsonl
```

---

## Advanced: Custom Processing Order

Current order is: **Sanitize → Dedup → PII → Lang**

To run in a different order or skip stages:

```bash
# Just sanitize + dedup (skip PII and lang)
python tools/clean_by_domain.py sanitize "Security Operations"
python tools/clean_by_domain.py dedup "Security Operations"

# You could also manually edit records at any intermediate stage
```

---

## Troubleshooting

### Q: How do I see what records were dropped?
A: All records are kept in the output files. If a record is dropped by a stage, it simply doesn't appear in the next stage's output. Compare record counts:
```bash
echo "Sanitize:"; wc -l cleaned_data/*/sanitize/*.jsonl
echo "Dedup:";    wc -l cleaned_data/*/dedup/*.jsonl
```

### Q: Can I restart a failed run?
A: Yes! Run the same command again. Each stage overwrites the previous output in that stage's folder.

### Q: How large will the output be?
A: Similar to input (each stage filters differently). The `--limit 20` test runs fast; full run processes all records.

---

## Full Workflow Recommendation

1. **Test with limit first** (5 minutes):
   ```bash
   python tools/clean_by_domain.py all --limit 20
   ```

2. **Run full clean** (depends on data size):
   ```bash
   python tools/clean_by_domain.py all
   ```

3. **Verify results**:
   ```bash
   ls -la cleaned_data/
   python tools/clean_by_domain.py report
   ```

4. **If something looks wrong, debug one stage**:
   ```bash
   python tools/clean_by_domain.py dedup "Security Operations" --limit 50
   ```

---

## Generated Files

All files go to: `cleaned_data/<domain>/<stage>/<filename>.jsonl`

Example paths:
- `cleaned_data/Security Operations/sanitize/sigma-rules.jsonl`
- `cleaned_data/Security Operations/dedup/sigma-rules.jsonl`
- `cleaned_data/Security Operations/pii/sigma-rules.jsonl`
- `cleaned_data/Security Operations/lang/sigma-rules.jsonl`
- `cleaned_data/Threat Intelligence/sanitize/cisa-kev.jsonl`
- etc.

Each file maintains the original JSON structure with records that passed that stage's filters.
