# Data Versioning with DVC

Every corpus release (`normalized/dataset.jsonl` + its manifest and audit sinks)
is versioned with **DVC** and stored on **S3**. Git tracks tiny `.dvc`/`dvc.lock`
pointers; the data lives in the remote. This is what makes a contaminated or
mis-licensed batch *scopeable and rollback-able* instead of forcing a full rebuild
(threat model Output: "Untraceable Contamination Scoping").

What is versioned (DVC scope = **outputs + reports**):
`normalized/dataset.jsonl`, `normalized/manifest.json`, the `rejected`/`duplicates`
sinks, and the EDA / normalize metrics. The large intermediate trees (`raw_data/`,
`clean_data/`, …) are re-derivable from the source allowlist + ledger and are left
out (see `.dvcignore`).

## One-time setup

```bash
uv sync --extra dev            # dvc[s3] comes via the toolchain, or: pip install 'dvc[s3]'
dvc init                       # creates .dvc/ (commit it)
dvc remote add -d s3 s3://<your-bucket>/dvc
dvc remote modify s3 region <your-region>
# auth: an IAM role (on ECS) or AWS_PROFILE / standard AWS env vars locally
git add .dvc .dvcignore dvc.yaml && git commit -m "Init DVC + S3 remote"
```

## Build, version, push

```bash
dvc repro                      # runs `cybersec-slm all`, records outputs in dvc.lock
git add dvc.lock && git commit -m "corpus build <date>"
dvc push                       # upload the versioned outputs to S3
```

The Prefect flow's `dvc_snapshot` task runs `dvc repro` + `dvc push` automatically
when `--dvc-push` is set (`cybersec-slm flow --dvc-push`).

## Roll back / scope a release

```bash
dvc metrics show                       # current EDA / normalize metrics
dvc metrics diff HEAD~1                # what changed between releases
git checkout <good-commit> dvc.lock    # pin a previous release
dvc checkout                           # restore that dataset.jsonl from S3
```

To scope a contaminated source: read its rows from `logs/provenance/ledger.csv`
and `normalized/manifest.json`, remove that source from `sources/allowlist.yaml`,
and `dvc repro` to rebuild without it — the rest of the corpus is unaffected.
