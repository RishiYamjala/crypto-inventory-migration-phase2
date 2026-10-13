"""Safe, local cryptographic asset discovery for explicitly authorized test directories.

This module never scans networks, contacts hosts, or reads outside the directory supplied
by the caller. It is a lightweight evidence collector, not an enterprise vulnerability
scanner. Discovered records should be reviewed before entering the inventory pipeline.
"""
from pathlib import Path
import re
import pandas as pd

PATTERNS = {
    "RSA-2048": re.compile(r"\bRSA(?:[- ]?2048)\b", re.I),
    "RSA-3072": re.compile(r"\bRSA(?:[- ]?3072)\b", re.I),
    "ECDH P-256": re.compile(r"\b(?:ECDH|P-256)\b", re.I),
    "ECDSA P-256": re.compile(r"\bECDSA(?:[- ]?P[- ]?256)?\b", re.I),
    "Ed25519": re.compile(r"\bEd25519\b", re.I),
    "AES-128": re.compile(r"\bAES[- ]?128\b", re.I),
    "AES-256": re.compile(r"\bAES[- ]?256\b", re.I),
    "3DES": re.compile(r"\b(?:3DES|Triple-DES)\b", re.I),
    "SHA-1": re.compile(r"\bSHA[- ]?1\b", re.I),
    "SHA-256": re.compile(r"\bSHA[- ]?256\b", re.I),
}


def _usage_for(path, text):
    label = f"{path.name} {text}".lower()
    if any(x in label for x in ("tls", "https", "certificate", ".pem")):
        return "TLS/HTTPS"
    if any(x in label for x in ("vpn", "wireguard")):
        return "VPN"
    if any(x in label for x in ("ssh", ".pub")):
        return "SSH"
    if any(x in label for x in ("sign", "firmware")):
        return "Digital Signatures"
    if any(x in label for x in ("database", "db", "encrypt")):
        return "Database Encryption"
    return "Configuration Evidence"


def discover_directory(directory, default_sensitivity="Medium", default_lifespan="1-5 years"):
    """Discover algorithm mentions under an explicitly authorized local directory.

    Returns one row per algorithm mention with source-file evidence. Binary files,
    symlinks, and files larger than ten megabytes are skipped to avoid following links
    outside the caller-supplied directory and to keep this beginner-friendly and safe.
    """
    root = Path(directory).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Authorized discovery directory does not exist: {root}")
    records = []
    for path in sorted(root.rglob("*")):
        # Do not follow symlinks: a file link could point outside the authorized root.
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 10_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for algorithm, pattern in PATTERNS.items():
            match = pattern.search(text)
            if match:
                records.append({
                    "asset_name": path.stem.replace("_", " ").title(),
                    "algorithm": algorithm,
                    "usage": _usage_for(path, text),
                    "sensitivity": default_sensitivity,
                    "lifespan": default_lifespan,
                    "evidence_source": str(path.relative_to(root)),
                    "evidence_excerpt": text[max(0, match.start()-30):match.end()+50].replace("\n", " ").strip(),
                })
    return pd.DataFrame(records, columns=["asset_name", "algorithm", "usage", "sensitivity", "lifespan", "evidence_source", "evidence_excerpt"])
