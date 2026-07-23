import contextlib
import json
import os
import shutil
import socket
import subprocess
import time

from ..core import DATA_ROOT, LOGS, logger

AV_LOG = os.path.join(LOGS, "av_scan.jsonl")


class Quarantined(Exception):
    """Raised when a file fails malware scanning and is quarantined."""
    pass


class ScanError(Exception):
    """Raised when a scan cannot complete (unreadable file, clamd drops, etc.).

    The spec says "reject/quarantine, never process anyway".  A scan that
    cannot run is *not* a clean bill of health, so callers must treat this
    as a hard failure — the source must not advance to light-EDA or cleaning.
    """


def _enforced() -> bool:
    """Return True if AV scanning is enforced (default), False if disabled."""
    return os.environ.get("CYBERSEC_SLM_ENFORCE_AV_SCAN", "1") != "0"


@contextlib.contextmanager
def ephemeral_clamav():
    """Spin up ClamAV for the duration of this context, then destroy it.

    No-op if CYBERSEC_SLM_ENFORCE_AV_SCAN is disabled.
    """
    if not _enforced():
        yield
        return

    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    compose_file = os.path.join(repo_root, "docker-compose.clamav.yml")
    if not os.path.exists(compose_file):
        compose_file = "docker-compose.clamav.yml"

    logger.info("  av scan: starting ephemeral ClamAV container...")
    try:
        subprocess.run(["docker", "compose", "-f", compose_file, "up", "-d", "--wait"],
                       check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"  av scan: failed to start ephemeral ClamAV container: {e.stderr.decode()}")
        raise RuntimeError(f"failed to start ephemeral clamav: {e.stderr.decode()}") from e

    try:
        yield
    finally:
        logger.info("  av scan: tearing down ephemeral ClamAV container...")
        subprocess.run(["docker", "compose", "-f", compose_file, "down", "-v"],
                       check=False, capture_output=True)


def _client() -> socket.socket:
    """A connected clamd client over TCP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(("127.0.0.1", 3310))
        return sock
    except OSError as e:
        raise RuntimeError("clamd is not reachable on 127.0.0.1:3310") from e


def _scan_stream(sock: socket.socket, data: bytes) -> str | None:
    """Send data to clamd using INSTREAM and return the finding (or None)."""
    sock.sendall(b"zINSTREAM\0")
    import struct
    # Send chunks
    chunk_size = 8192
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        sock.sendall(struct.pack(">L", len(chunk)) + chunk)
    sock.sendall(struct.pack(">L", 0))

    resp = sock.recv(1024)
    if b"FOUND" in resp:
        # e.g., stream: Eicar-Test-Signature FOUND
        parts = resp.decode().strip().split(" ")
        return parts[1] if len(parts) > 1 else "Malware.Unknown"
    return None


def quarantine(folder: str, finding: str) -> None:
    """Move an entire source folder into data/quarantine/."""
    if not os.path.exists(folder):
        return
    rel = os.path.relpath(folder, os.path.dirname(os.path.dirname(folder)))
    dest = os.path.join(DATA_ROOT, "quarantine", rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    try:
        shutil.move(folder, dest)
        logger.warning(f"  av scan: QUARANTINED source -> {dest} (finding: {finding})")
    except Exception as e:
        logger.error(f"  av scan: failed to quarantine {folder}: {e}")

    with open(AV_LOG, "a", encoding="utf-8") as f:
        json.dump({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "target": folder,
            "finding": finding,
            "action": "quarantine_source"
        }, f)
        f.write("\n")
    raise Quarantined(f"Source quarantined due to finding: {finding}")


def quarantine_file(path: str, finding: str) -> None:
    """Move a single file into data/quarantine/."""
    if not os.path.exists(path):
        return
    dest = os.path.join(DATA_ROOT, "quarantine", os.path.basename(path))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    try:
        shutil.move(path, dest)
        logger.warning(f"  av scan: QUARANTINED file -> {dest} (finding: {finding})")
    except Exception as e:
        logger.error(f"  av scan: failed to quarantine {path}: {e}")

    with open(AV_LOG, "a", encoding="utf-8") as f:
        json.dump({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "target": path,
            "finding": finding,
            "action": "quarantine_file"
        }, f)
        f.write("\n")
    raise Quarantined(f"File quarantined due to finding: {finding}")


def gate_file(path: str) -> bool:
    """Scan a single file, quarantine it if malicious."""
    if not _enforced():
        return True

    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        logger.error(f"  av scan: could not read {path}: {e}")
        raise ScanError(f"could not read {path}: {e}") from e

    sock = _client()
    try:
        finding = _scan_stream(sock, data)
        if finding:
            quarantine_file(path, finding)
    except Quarantined:
        raise
    except Exception as e:
        logger.error(f"  av scan: could not scan {path}: {e}")
        raise ScanError(f"could not scan {path}: {e}") from e
    finally:
        sock.close()
    return True


def gate(folder: str) -> bool:
    """Scan an entire folder, quarantine the whole folder if any file is malicious."""
    if not _enforced():
        return True

    sock = _client()
    try:
        for root, _, files in os.walk(folder):
            for name in files:
                filepath = os.path.join(root, name)
                try:
                    with open(filepath, "rb") as f:
                        data = f.read()
                    finding = _scan_stream(sock, data)
                    if finding:
                        quarantine(folder, finding)
                except Quarantined:
                    raise
                except Exception as e:
                    logger.error(f"  av scan: could not scan {filepath}: {e}")
                    raise ScanError(
                        f"could not scan {filepath}: {e}"
                    ) from e
    finally:
        sock.close()
    return True
