# Storage Strategy

## JSONL
- Use during collection and extraction
- One record per line, easy to stream and append
- Human readable, easy to debug
- Stored in /raw_data/{source_id}/{YYYY-MM-DD}/

## Parquet
- Use after collection is done, before training
- Compressed, fast to query, handles large scale well
- Not human readable but much smaller file size
- Used when combining all sources into final dataset

## Rule of thumb
Collect in JSONL. Store at scale in Parquet.