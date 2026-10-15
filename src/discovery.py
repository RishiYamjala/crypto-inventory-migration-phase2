"""Evidence-oriented static discovery of target public-key cryptography.

Scans only a caller-supplied local directory. It does not execute source code,
follow symlinks, access networks, or claim to be a complete cryptographic parser.
Findings are line-level candidates and require human review.
"""
from pathlib import Path
import re
import pandas as pd

# Target public-key algorithms for the PS-P2 scanner. Hash-only and symmetric
# findings are deliberately outside these scanner metrics.
PATTERNS = {
    "RSA-2048": re.compile(r"\bRSA[- ]?2048\b|\bdefault_bits\s*=\s*2048\b|\bopenssl\s+genrsa\b[^\n]*\b2048\b", re.I),
    "RSA-3072": re.compile(r"\bRSA[- ]?3072\b|\bopenssl\s+genrsa\b[^\n]*\b3072\b", re.I),
    "RSA": re.compile(r"\brsa\.generate_private_key\b|\bopenssl\s+(?:genrsa|rsa)\b|\bRSAPrivateKey\b|\bRSAPublicKey\b|\brsa\.new\s*\(", re.I),
    "DSA": re.compile(r"\bdsa\.generate_private_key\b|\bDSA(?:ParameterNumbers|PrivateKey|PublicKey)\b|\bopenssl\s+(?:dsaparam|gendsa)\b|(?<!ML-)\bDSA\b", re.I),
    "DH": re.compile(r"\bdh\.generate_parameters\b|\bDHParameterNumbers\b|\bDiffie[- ]Hellman\b|\bopenssl\s+dhparam\b|\bDH(?:PrivateKey|PublicKey)\b|\bX9\.42\b", re.I),
    "ECDH": re.compile(r"\bECDH\b|\bX25519\b|\bX448\b|\bXDH\b", re.I),
    "ECDSA": re.compile(r"\bECDSA\b|\becdsa\.ECDSA\b", re.I),
    "ECC": re.compile(r"\bEllipticCurve(Private|Public)Key\b|\bsecp(?:192|224|256|384|521)[rk]?\d*\b|\bprime256v1\b|\bP-256\b", re.I),
}


def _role_and_migration(algorithm, line):
    lower = line.lower()
    if algorithm.startswith("RSA"):
        if any(token in lower for token in ("sign", "verify", "certificate", "x509", "jwt", "code signing")):
            return ("public-key; signature use suggested by context, confirm manually",
                    "FIPS 204 ML-DSA for signatures; FIPS 203 ML-KEM only if key establishment is also present")
        if any(token in lower for token in ("encrypt", "decrypt", "key exchange", "tls", "https", "transport")):
            return ("public-key; encryption/key-transport context suggested, confirm manually",
                    "FIPS 203 ML-KEM for key establishment; FIPS 204 ML-DSA for signatures where applicable")
        return ("RSA public-key use; role unknown",
                "Role review required: FIPS 203 ML-KEM for key establishment; FIPS 204 ML-DSA for signatures")
    if algorithm in {"DSA", "ECDSA"}:
        return ("digital signature/authentication candidate",
                "FIPS 204 ML-DSA; consider FIPS 205 SLH-DSA where policy and lifecycle justify it")
    if algorithm in {"DH", "ECDH"}:
        return ("key-establishment/key-agreement candidate",
                "FIPS 203 ML-KEM (consider hybrid transition where required)")
    if algorithm == "ECC":
        if any(token in lower for token in ("sign", "verify", "certificate", "x509")):
            return ("elliptic-curve use; signature context suggested, confirm manually",
                    "FIPS 204 ML-DSA for signatures; confirm the exact ECC role")
        if any(token in lower for token in ("derive", "exchange", "agreement", "tls", "https")):
            return ("elliptic-curve use; key-agreement context suggested, confirm manually",
                    "FIPS 203 ML-KEM for key establishment; confirm the exact ECC role")
        return ("elliptic-curve use; role unknown",
                "Manual role review: FIPS 203 ML-KEM for key establishment or FIPS 204 ML-DSA for signatures")
    return ("public-key use; role unknown", "Manual role review required")


def _usage_for(path, text):
    label = f"{path.name} {text}".lower()
    if any(x in label for x in ("tls", "https", "certificate", ".pem")):
        return "TLS/HTTPS"
    if any(x in label for x in ("vpn", "wireguard")):
        return "VPN"
    if any(x in label for x in ("ssh", ".pub")):
        return "SSH"
    if any(x in label for x in ("sign", "firmware", "verify")):
        return "Digital Signatures"
    if any(x in label for x in ("database", "db", "encrypt")):
        return "Database Encryption"
    return "Configuration Evidence"


def discover_directory(directory, default_sensitivity="Medium", default_lifespan="1-5 years"):
    """Return one candidate per target algorithm per source line, with evidence."""
    root = Path(directory).expanduser().resolve()
    if not root.is_dir():
        raise NotADirectoryError(f"Authorized discovery directory does not exist: {root}")
    records = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            if path.stat().st_size > 10_000_000:
                continue
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line_number, line in enumerate(source.splitlines(), start=1):
            matches = [(algorithm, pattern.search(line)) for algorithm, pattern in PATTERNS.items()]
            matched_names = {algorithm for algorithm, match in matches if match}
            # Prefer size-specific labels for explicitly sized OpenSSL key generation.
            if "RSA-2048" in matched_names or "RSA-3072" in matched_names:
                matched_names.discard("RSA")
            for algorithm, match in matches:
                if not match or (algorithm == "RSA" and algorithm not in matched_names):
                    continue
                role, migration = _role_and_migration(algorithm, line)
                records.append({
                    "asset_name": path.stem.replace("_", " ").title(),
                    "algorithm": algorithm,
                    "usage": _usage_for(path, line),
                    "sensitivity": default_sensitivity,
                    "lifespan": default_lifespan,
                    "evidence_source": path.relative_to(root).as_posix(),
                    "line_number": line_number,
                    "matched_pattern": match.group(0),
                    "evidence_excerpt": line.strip()[:500],
                    "cryptographic_role": role,
                    "fips_migration": migration,
                })
    return pd.DataFrame(records, columns=[
        "asset_name", "algorithm", "usage", "sensitivity", "lifespan",
        "evidence_source", "line_number", "matched_pattern", "evidence_excerpt",
        "cryptographic_role", "fips_migration",
    ])
