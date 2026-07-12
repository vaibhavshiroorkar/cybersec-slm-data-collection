#!/usr/bin/env python3
"""Unified dataset fetcher -> data/raw/<domain>/<owner>/ (original + jsonl).

One handler per source kind (hf, kaggle, github, url), all sharing common.py.
The per-source streaming worker (:func:`cybersec_slm.ingestion.worker.process_source`)
calls these handlers.
"""

import os
import shutil
from urllib.parse import urlparse

from .common import (
    EXT_PRIORITY,
    ONE_MB,
    RAW_DATA,
    SKIP_SUBSTRINGS,
    category_of,
    count_lines,
    download,
    group_key,
    logger,
    sha256_file,
    to_jsonl,
)

BASE = RAW_DATA


def _github_target(url: str) -> tuple[str, str] | None:
    """Resolve a github.com URL to something downloadable + a filename.

    Repo root / tree URLs point at a *page*, not a file, so rewrite them to the
    branch archive zip (processed by the zip path below). ``/blob/`` URLs become
    their raw-file equivalent. Direct ``raw.githubusercontent.com`` links and
    file URLs return None (handled as-is). Returns ``(download_url, name)``.
    """
    p = urlparse(url)
    if p.netloc not in ("github.com", "www.github.com"):
        return None
    parts = [x for x in p.path.split("/") if x]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1][:-4] if parts[1].endswith(".git") else parts[1]
    if len(parts) == 2:                       # owner/repo  -> default branch zip
        return f"https://github.com/{owner}/{repo}/archive/HEAD.zip", f"{repo}.zip"
    if parts[2] == "tree" and len(parts) >= 4:   # .../tree/<branch>[/subdir]
        return (f"https://github.com/{owner}/{repo}/archive/refs/heads/{parts[3]}.zip",
                f"{repo}.zip")
    if parts[2] == "blob" and len(parts) >= 5:   # .../blob/<branch>/<path> -> raw
        branch, rest = parts[3], "/".join(parts[4:])
        return (f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{rest}",
                os.path.basename(rest))
    return None


def _download_name(url: str) -> str:
    """A non-empty download filename for ``url``, even when it ends in '/'.

    Trailing-slash export endpoints (e.g. abuse.ch ``/export/csv/full/``) have no
    basename, so ``os.path.basename`` returns '' and the download target collapses
    to the folder itself (``open(dir)`` -> FileNotFoundError). Fall back to the
    last non-empty path segment so the file gets a real name.
    """
    base = os.path.basename(urlparse(url).path.rstrip("/"))
    return base or "download"


def _is_zipfile(path: str) -> bool:
    """True when ``path`` begins with the ZIP local-file magic (``PK\\x03\\x04``).

    Some endpoints serve a zip from an extensionless / trailing-slash URL
    (Content-Type: application/zip), so the '.zip' suffix check alone misses them;
    sniff the magic bytes to route those through the zip-extraction path too.
    """
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"PK\x03\x04"
    except OSError:
        return False


def _folder(domain, owner, name, counts):
    base = owner if counts.get(owner, 0) <= 1 else f"{owner}-{name}"
    d = os.path.join(BASE, domain, base)
    os.makedirs(d, exist_ok=True)
    return d


def _convert_and_log(original, jsonl, log, *, kind, name, domain, desc, url, lic):
    """Convert one original file -> jsonl, record provenance."""
    fmt = os.path.splitext(original)[1].lstrip(".")
    orig_mb = os.path.getsize(original) / ONE_MB
    meta = dict(kind=kind, name=name, category=category_of(kind), domain=domain,
                description=desc, source_url=url, origin_format=fmt, license=lic)
    record_meta = {"source": desc, "url": url, "license": lic}
    size = to_jsonl(original, jsonl, meta=record_meta)
    rows = count_lines(jsonl)
    logger.info(f"  {os.path.basename(jsonl)}: {rows:,} rows, {size/ONE_MB:.1f} MB")
    log.record(**meta, orig_mb=round(orig_mb, 1), jsonl_mb=round(size / ONE_MB, 1),
               rows=rows, sha256=sha256_file(jsonl), status="ok")


def _combine_to_jsonl(paths, jsonl, log, *, kind, name, domain, desc, url, lic, origin_fmt):
    """Convert and append every file in ``paths`` into a single ``jsonl``.

    Used for archive/repo sources (github + zip) so a repo that stores its data
    as many small files (e.g. iann0036/iam-dataset) collapses into one output
    instead of one-jsonl-per-file. The source is recorded once.
    """
    record_meta = {"source": desc, "url": url, "license": lic}
    meta = dict(kind=kind, name=name, category=category_of(kind), domain=domain,
                description=desc, source_url=url, origin_format=origin_fmt, license=lic)
    open(jsonl, "wb").close()
    orig_total = 0
    for path in paths:
        tmp = jsonl + ".part"
        try:
            to_jsonl(path, tmp, meta=record_meta)
            if not os.path.exists(tmp):       # reader skipped it (e.g. oversize)
                continue
            with open(tmp, "rb") as src, open(jsonl, "ab") as dst:
                shutil.copyfileobj(src, dst)
            orig_total += os.path.getsize(path)
        except Exception as ex:               # one bad member must not fail the source
            logger.warning(f"  skip unreadable member {os.path.basename(path)}: "
                           f"{type(ex).__name__}: {ex}")
            continue
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
    size = os.path.getsize(jsonl)
    rows = count_lines(jsonl)
    logger.info(f"  {os.path.basename(jsonl)}: {rows:,} rows, {size/ONE_MB:.1f} MB "
                f"({len(paths)} files)")
    log.record(**meta, orig_mb=round(orig_total / ONE_MB, 1),
               jsonl_mb=round(size / ONE_MB, 1), rows=rows,
               sha256=sha256_file(jsonl), status="ok")


# ------------------------------------------------------------ handlers -------
def fetch_hf(ref, domain, desc, lic, folder, log):
    from huggingface_hub import HfApi
    info = HfApi().dataset_info(ref, files_metadata=True)
    sib = {s.rfilename: (s.size or 0) for s in info.siblings}
    cand = [f for f in sib if f.lower().endswith(EXT_PRIORITY)
            and not any(s in f.lower() for s in SKIP_SUBSTRINGS)]
    for ext in EXT_PRIORITY:
        chosen = [f for f in cand if f.lower().endswith(ext)]
        if chosen:
            break
    # Group sharded files (train-00000-of-N...) so they accumulate into one jsonl
    # instead of overwriting each other.
    groups = {}
    for rel in chosen:
        groups.setdefault(group_key(rel), []).append(rel)

    for key, members in groups.items():
        name = f"{ref.split('/')[-1]}/{key}"
        url0 = f"https://huggingface.co/datasets/{ref}/resolve/main/{members[0]}"
        fext = os.path.splitext(members[0])[1]
        meta = dict(kind="hf", name=name, category=category_of("hf"), domain=domain,
                    description=desc, source_url=url0, origin_format=fext.lstrip("."),
                    license=lic)
        jsonl = os.path.join(folder, key + ".jsonl")
        open(jsonl, "wb").close()
        total = rows = orig_total = 0
        shard_meta = {"source": desc, "url": url0, "license": lic}
        for i, rel in enumerate(sorted(members)):
            url = f"https://huggingface.co/datasets/{ref}/resolve/main/{rel}"
            orig = os.path.join(folder, (key if len(members) == 1 else f"{key}.part{i}")
                                + (".original.jsonl" if fext == ".jsonl" else fext))
            download(url, orig)
            tmp = jsonl + ".part"
            try:
                to_jsonl(orig, tmp, meta=shard_meta)
                if not os.path.exists(tmp):    # reader skipped it (e.g. oversize)
                    continue
                with open(tmp, "rb") as src, open(jsonl, "ab") as dst:
                    shutil.copyfileobj(src, dst)
                orig_total += os.path.getsize(orig)
            except Exception as ex:            # one bad shard must not fail the source
                logger.warning(f"  skip unreadable shard {os.path.basename(orig)}: "
                               f"{type(ex).__name__}: {ex}")
                continue
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)
            total = os.path.getsize(jsonl)
        rows = count_lines(jsonl)
        logger.info(f"  {key}.jsonl: {rows:,} rows, {total/ONE_MB:.1f} MB"
                    + (f" ({len(members)} shards)" if len(members) > 1 else ""))
        log.record(**meta, orig_mb=round(orig_total / ONE_MB, 1),
                   jsonl_mb=round(total / ONE_MB, 1), rows=rows,
                   sha256=sha256_file(jsonl), status="ok")


def fetch_kaggle(ref, domain, desc, lic, folder, log):
    from kaggle.api.kaggle_api_extended import KaggleApi
    api = KaggleApi(); api.authenticate()
    files = api.dataset_list_files(ref).files
    sizes = {f.name: (getattr(f, "totalBytes", None) or getattr(f, "total_bytes", 0) or 0)
             for f in files}
    cand = [n for n in sizes if n.lower().endswith(EXT_PRIORITY)
            and not any(s in n.lower() for s in SKIP_SUBSTRINGS)]
    for ext in EXT_PRIORITY:
        chosen = [f for f in cand if f.lower().endswith(ext)]
        if chosen:
            break
    url = f"https://www.kaggle.com/datasets/{ref}"
    tmp = os.path.join(folder, "_dl"); os.makedirs(tmp, exist_ok=True)
    for rel in sorted(chosen):
        stem, fext = os.path.splitext(os.path.basename(rel))[0], os.path.splitext(rel)[1]
        name = f"{ref.split('/')[-1]}/{stem}"
        api.dataset_download_file(ref, rel, path=tmp, quiet=True)
        got = os.path.join(tmp, os.path.basename(rel))
        if not os.path.exists(got) and os.path.exists(got + ".zip"):
            import zipfile
            with zipfile.ZipFile(got + ".zip") as z:
                z.extractall(tmp)
        if not os.path.exists(got):
            logger.error(f"  download missing: {rel}"); continue
        orig = os.path.join(folder, os.path.basename(rel))
        shutil.move(got, orig)
        _convert_and_log(orig, os.path.join(folder, stem + ".jsonl"), log,
                         kind="kaggle", name=name, domain=domain, desc=desc, url=url, lic=lic)
    shutil.rmtree(tmp, ignore_errors=True)


def fetch_url(url, domain, desc, lic, folder, log, kind="url"):
    gh = _github_target(url)
    if gh:
        url, name = gh           # repo page -> archive zip / raw file
    else:
        name = _download_name(url)
    stem, fext = os.path.splitext(name)
    orig = os.path.join(folder, name)
    download(url, orig)
    if orig.lower().endswith(".zip") or _is_zipfile(orig):
        import zipfile
        zdir = os.path.join(folder, "_z"); os.makedirs(zdir, exist_ok=True)
        with zipfile.ZipFile(orig) as z:
            z.extractall(zdir)
        os.remove(orig)
        data = [os.path.join(r, f) for r, _d, fs in os.walk(zdir) for f in fs
                if f.lower().endswith(EXT_PRIORITY)
                and not any(s in f.lower() for s in SKIP_SUBSTRINGS)]
        for ext in EXT_PRIORITY:
            data = [f for f in data if f.lower().endswith(ext)] or data
            if any(f.lower().endswith(ext) for f in data):
                break
        # Concatenate every matching file into ONE jsonl per source. A repo that
        # stores its data across thousands of small files otherwise explodes into
        # thousands of outputs; collapse it to a single <source>.jsonl.
        if data:
            origin_fmt = os.path.splitext(data[0])[1].lstrip(".")
            _combine_to_jsonl(sorted(data), os.path.join(folder, stem + ".jsonl"), log,
                              kind=kind, name=stem, domain=domain, desc=desc, url=url,
                              lic=lic, origin_fmt=origin_fmt)
        else:
            logger.warning(f"  no data files inside {stem}.zip")
        shutil.rmtree(zdir, ignore_errors=True)
        return
    _convert_and_log(orig, os.path.join(folder, stem + ".jsonl"), log,
                     kind=kind, name=stem, domain=domain, desc=desc, url=url, lic=lic)
