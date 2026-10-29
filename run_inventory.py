#!/usr/bin/env python3
"""Offline cryptographic inventory classifier and migration planner.

Standard-library-only CLI:
    python run_inventory.py --input inventory.csv --output predictions.csv

The output schema is intentionally fixed. This is a transparent heuristic, not a
substitute for the organizer's labeled dataset/evaluator or a cryptographic audit.
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path
from typing import Any

LABELS = {
    "QUANTUM_VULNERABLE",
    "QUANTUM_RESISTANT",
    "HYBRID",
    "SYMMETRIC_OR_HASH",
    "LEGACY_BROKEN",
    "UNKNOWN",
}
OUTPUT_COLUMNS = [
    "asset_id", "predicted_label", "priority_score", "priority_rank",
    "recommended_action", "migration_wave", "depends_on", "rationale",
]

ALIASES = {
    "asset_id": ("asset_id", "asset_identifier", "crypto_asset_id", "id"),
    "asset_name": ("asset_name", "name", "asset", "cryptographic_asset"),
    "algorithm": ("algorithm", "algorithm_name", "crypto_algorithm", "cryptographic_algorithm", "algorithm_used"),
    "primitive": ("primitive", "primitive_type", "cryptographic_role", "role", "function", "use_case"),
    "key_size_or_parameter_set": ("key_size_or_parameter_set", "parameter_set", "key_size", "key_length", "parameters", "parameter"),
    "internet_exposed": ("internet_exposed", "internet_facing", "internet_exposure", "exposure", "publicly_accessible"),
    "data_retention_years": ("data_retention_years", "retention_years", "data_retention", "retention", "retention_period", "retention_duration", "data_lifetime", "lifespan"),
    "criticality": ("criticality", "business_criticality", "asset_criticality", "importance"),
    "data_sensitivity": ("data_sensitivity", "sensitivity", "data_classification", "classification"),
    "depends_on": ("depends_on", "dependencies", "dependency", "dependent_assets"),
}

ROLE_ALIASES = {
    "keyestablishment": "key_establishment",
    "keyexchange": "key_establishment",
    "keyagreement": "key_establishment",
    "keyencapsulation": "key_establishment",
    "kem": "key_establishment",
    "signature": "digital_signature",
    "signatures": "digital_signature",
    "signing": "digital_signature",
    "sign": "digital_signature",
    "signaturegeneration": "digital_signature",
    "asymmetricsignature": "digital_signature",
    "authentication": "digital_signature",
    "digitalsignature": "digital_signature",
    "publickeyencryption": "public_key_encryption",
    "publickeyencrypt": "public_key_encryption",
    "encryption": "symmetric_encryption",
    "symmetricencryption": "symmetric_encryption",
    "symmetriccipher": "symmetric_encryption",
    "blockcipher": "symmetric_encryption",
    "cipher": "symmetric_encryption",
    "hashing": "hash",
    "integrity": "hash",
    "digest": "hash",
    "hashfunction": "hash",
    "mac": "mac",
    "hmac": "mac",
    "messageauthenticationcode": "mac",
    "kdf": "kdf",
    "keyderivation": "kdf",
    "keyderivationfunction": "kdf",
}
PUBLIC_KEY_ROLES = {"key_establishment", "digital_signature", "public_key_encryption"}
NON_PUBLIC_KEY_ROLES = {"hash", "symmetric_encryption", "mac", "kdf"}

LEGACY_MARKERS = ("MD2", "MD4", "MD5", "SHA1", "3DES", "TDEA", "DESEDE", "RC4", "RC2")
HASH_MARKERS = (
    "SHA224", "SHA256", "SHA384", "SHA512", "SHA3224", "SHA3256", "SHA3384",
    "SHA3512", "SHAKE128", "SHAKE256", "BLAKE2", "BLAKE3", "SM3", "WHIRLPOOL",
)
PQC_MARKERS = (
    "MLKEM", "KYBER", "MLDSA", "DILITHIUM", "SLHDSA", "SPHINCS",
    "FNDSA", "FALCON", "HQC", "LMS", "XMSS",
)


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _norm(value: Any) -> str:
    return re.sub(r"[^A-Z0-9]", "", _text(value).upper())


def _role(value: Any) -> str:
    key = re.sub(r"[^a-z0-9]", "", _text(value).lower())
    return ROLE_ALIASES.get(key, key)


def _first(row: dict[str, Any], names: tuple[str, ...] | list[str], default: str = "") -> str:
    for name in names:
        value = _text(row.get(name, ""))
        if value:
            return value
    return default


def _read_csv(path: str | Path) -> tuple[list[dict[str, str]], list[str]]:
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("Input CSV must have a header row")
        raw_headers = list(reader.fieldnames)
        if len(raw_headers) != len(set(raw_headers)):
            raise ValueError("Input CSV contains duplicate column names")
        normalized = [re.sub(r"[^a-z0-9]+", "_", h.strip().lower()).strip("_") for h in raw_headers]
        canonical_to_original: dict[str, str] = {}
        for canonical, candidates in ALIASES.items():
            matches = [raw_headers[i] for i, norm in enumerate(normalized) if norm in candidates]
            if len(matches) > 1:
                raise ValueError(f"Ambiguous input schema for '{canonical}': multiple columns {matches}")
            if matches:
                canonical_to_original[canonical] = matches[0]
        rows = []
        for raw in reader:
            row = {k: (v if v is not None else "") for k, v in raw.items() if k is not None}
            canonical = dict(row)
            for key, original in canonical_to_original.items():
                canonical[key] = _text(row.get(original, ""))
            rows.append(canonical)
    return rows, raw_headers


def classify_algorithm(value: Any, params: Any = "") -> str:
    """Classify an algorithm conservatively; role and parameter consistency are checked separately."""
    s = _norm(value)
    p = _norm(params)
    if not s or s in {"UNKNOWN", "VENDORMANAGED", "VENDORDEFAULT", "PROPRIETARY", "CUSTOM", "CUSTOMXORSCHEME", "NA"}:
        return "UNKNOWN"

    # Weak/deprecated algorithms take precedence over broad public-key markers.
    if any(marker in s for marker in LEGACY_MARKERS) or re.fullmatch(r"DES(?:CBC|ECB|CFB|OFB|CTR|XTS)?", s):
        return "LEGACY_BROKEN"

    has_pqc = False
    if "MLKEM" in s or "KYBER" in s:
        has_pqc = bool(re.search(r"(?:MLKEM|KYBER)(512|768|1024)", s) or p in {"512", "768", "1024"})
    elif "MLDSA" in s or "DILITHIUM" in s:
        has_pqc = bool(re.search(r"(?:MLDSA|DILITHIUM)(44|65|87|2|3|5)", s) or p in {"44", "65", "87", "2", "3", "5"})
    elif "FNDSA" in s or "FALCON" in s:
        has_pqc = bool(re.search(r"(?:FNDSA|FALCON)(512|1024)", s) or p in {"512", "1024"})
    elif "HQC" in s:
        has_pqc = bool(re.search(r"HQC(128|192|256)", s) or p in {"128", "192", "256"})
    elif any(x in s for x in ("SLHDSA", "SPHINCS")):
        has_pqc = True
    elif s.startswith("LMS") or s.startswith("XMSS"):
        has_pqc = True

    # DSA in ML-DSA/FN-DSA/SLH-DSA is not classical DSA.
    classical_markers = (
        "RSA", "ECDH", "ECDSA", "ECDHE", "ED25519", "ED448", "EDDSA",
        "X25519", "X448", "FFDHE", "MODP", "SECP", "P256", "P384", "P521",
        "DIFFIEHELLMAN", "ELGAMAL",
    )
    has_classical = any(marker in s for marker in classical_markers)
    if not has_classical and "DSA" in s and not any(x in s for x in ("MLDSA", "FNDSA", "SLHDSA")):
        has_classical = True
    if re.match(r"^DH(?:\d|$)", s):
        has_classical = True

    if has_pqc and has_classical:
        return "HYBRID"
    if "HYBRID" in s and has_pqc:
        return "HYBRID"
    if has_pqc:
        return "QUANTUM_RESISTANT"
    if has_classical:
        return "QUANTUM_VULNERABLE"
    if (
        "AES" in s or "CHACHA20" in s or "POLY1305" in s or "SM4" in s
        or any(marker in s for marker in HASH_MARKERS)
        or s.startswith(("HMAC", "HKDF", "PBKDF2", "SCRYPT", "ARGON2", "CMAC", "GMAC", "KMAC"))
    ):
        return "SYMMETRIC_OR_HASH"
    return "UNKNOWN"


def _parameter_issue(algorithm: Any, params: Any) -> bool:
    """Return True only when supplied parameter metadata is invalid or contradictory."""
    a, p = _norm(algorithm), _norm(params)
    if not p:
        # A fully specified algorithm name can stand on its own.
        return False

    specifications = (
        (r"(?:MLKEM|KYBER)(512|768|1024)", {"512", "768", "1024"}, "ML-KEM/Kyber"),
        (r"(?:MLDSA)(44|65|87)", {"44", "65", "87"}, "ML-DSA"),
        (r"(?:FNDSA|FALCON)(512|1024)", {"512", "1024"}, "FN-DSA/Falcon"),
        (r"HQC(128|192|256)", {"128", "192", "256"}, "HQC"),
    )
    for pattern, allowed, _name in specifications:
        match = re.search(pattern, a)
        if match:
            supplied = re.fullmatch(r"(512|768|1024|44|65|87|128|192|256)", p)
            if supplied and supplied.group(1) not in allowed:
                return True
            if supplied and supplied.group(1) != match.group(1):
                return True

    if "MLKEM" in a or "KYBER" in a:
        if p not in {"512", "768", "1024"} and not re.fullmatch(r"(?:MLKEM|KYBER)(512|768|1024)", p):
            return True
        embedded = re.search(r"(?:MLKEM|KYBER)(512|768|1024)", a)
        supplied = re.search(r"(512|768|1024)", p)
        if embedded and supplied and embedded.group(1) != supplied.group(1):
            return True
    if "MLDSA" in a:
        if p not in {"44", "65", "87"} and not re.fullmatch(r"MLDSA(44|65|87)", p):
            return True
        embedded = re.search(r"MLDSA(44|65|87)", a)
        supplied = re.search(r"(44|65|87)", p)
        if embedded and supplied and embedded.group(1) != supplied.group(1):
            return True
    if "SLHDSA" in a and not re.fullmatch(r"(?:SHA2|SHAKE)(?:128|192|256)(?:S|F)?", p):
        return True
    if a.startswith("LMS") and not re.fullmatch(r"(?:LMS)?SHA(?:256|512)M(?:32|24)H(?:5|10|15|20|25)", p):
        return True
    if a.startswith("XMSS") and not re.fullmatch(r"(?:XMSS)?SHA2?(?:10|16|20)(?:256|512)", p):
        return True

    # Explicit AES key-size conflicts are invalid metadata.
    if "AES" in a and p.isdigit():
        if p not in {"128", "192", "256"}:
            return True
        embedded = re.search(r"AES(128|192|256)", a)
        if embedded and embedded.group(1) != p:
            return True
    return False


def classify_record(row: dict[str, Any]) -> str:
    algorithm = _first(row, ("algorithm",))
    primitive = _role(_first(row, ("primitive", "cryptographic_role", "role")))
    params = _first(row, ("key_size_or_parameter_set", "parameter_set", "key_size"))
    label = classify_algorithm(algorithm, params)
    if label == "UNKNOWN" or _parameter_issue(algorithm, params):
        return "UNKNOWN"

    norm_alg = _norm(algorithm)
    has_hash = any(marker in norm_alg for marker in HASH_MARKERS) or norm_alg.startswith(("MD2", "MD4", "MD5"))
    has_symmetric = any(marker in norm_alg for marker in ("AES", "CHACHA20", "SM4", "DES", "TDEA", "DESEDE", "RC2", "RC4"))
    has_mac = any(marker in norm_alg for marker in ("HMAC", "CMAC", "GMAC", "POLY1305", "KMAC"))
    has_kdf = norm_alg.startswith(("HKDF", "PBKDF2", "SCRYPT", "ARGON2", "CONCATKDF", "SP800108"))
    has_signature = any(marker in norm_alg for marker in (
        "ECDSA", "ED25519", "ED448", "EDDSA", "MLDSA", "DILITHIUM",
        "FNDSA", "FALCON", "SLHDSA", "SPHINCS", "LMS", "XMSS", "RSA", "DSA",
    )) and not any(marker in norm_alg for marker in ("OAEP", "RSAENCRYPT", "RSAES"))
    has_key_establishment = any(marker in norm_alg for marker in (
        "RSA", "ECDH", "ECDHE", "X25519", "X448", "DIFFIEHELLMAN", "FFDHE", "MODP",
        "MLKEM", "KYBER", "HQC",
    )) or re.match(r"^DH(?:\d|$)", norm_alg) is not None

    if primitive in PUBLIC_KEY_ROLES and label in {"SYMMETRIC_OR_HASH", "LEGACY_BROKEN"}:
        return "UNKNOWN"
    if primitive in NON_PUBLIC_KEY_ROLES and label in {"QUANTUM_VULNERABLE", "QUANTUM_RESISTANT", "HYBRID"}:
        return "UNKNOWN"
    if primitive == "digital_signature" and not has_signature:
        return "UNKNOWN"
    if primitive == "key_establishment" and not has_key_establishment:
        return "UNKNOWN"
    if primitive == "public_key_encryption" and not any(x in norm_alg for x in ("RSA", "ELGAMAL", "PAILLIER", "MLKEM", "KYBER")):
        return "UNKNOWN"
    if primitive == "symmetric_encryption" and not has_symmetric:
        return "UNKNOWN"
    if primitive == "hash" and (not has_hash or has_symmetric):
        return "UNKNOWN"
    if primitive == "mac" and not has_mac:
        return "UNKNOWN"
    if primitive == "kdf" and not has_kdf:
        return "UNKNOWN"
    return label


def _yes(value: Any) -> bool | None:
    s = _text(value).lower().replace("_", "-")
    if s in {"yes", "true", "1", "y", "internet", "internet-exposed", "internet-facing", "public-facing", "externally-exposed", "external", "exposed", "public"}:
        return True
    if s in {"no", "false", "0", "n", "internal", "not-exposed", "not-internet-facing", "private", "not internet-facing", "not public-facing", "unexposed"}:
        return False
    return None


def _retention_years(row: dict[str, Any]) -> float | None:
    raw = _first(row, ("data_retention_years", "retention_years", "retention", "data_retention", "retention_period", "lifespan", "retention_duration", "data_lifetime"))
    if not raw:
        return None
    s = raw.lower()
    if any(word in s for word in ("permanent", "indefinite", "forever")):
        return 10.0
    numbers = re.findall(r"\d+(?:\.\d+)?", s)
    if not numbers:
        return None
    years = max(float(number) for number in numbers)
    if "month" in s:
        years /= 12
    elif "week" in s:
        years /= 52.1429
    elif "day" in s:
        years /= 365
    elif "year" not in s and years > 100:
        years /= 365
    return max(0.0, years)


def _score(row: dict[str, Any], label: str) -> int:
    """Apply the task's additive score exactly, then cap it at 100."""
    base = {
        "QUANTUM_VULNERABLE": 40,
        "LEGACY_BROKEN": 35,
        "UNKNOWN": 20,
        "HYBRID": 15,
        "QUANTUM_RESISTANT": 5,
        "SYMMETRIC_OR_HASH": 5,
    }[label]
    exposure_bonus = 25 if _yes(_first(row, ("internet_exposed",))) is True else 10
    years = _retention_years(row)
    retention_bonus = 20 if years is not None and years >= 10 else 10 if years is not None and years >= 5 else 5
    criticality = _first(row, ("criticality",)).lower()
    criticality_bonus = 15 if criticality == "critical" else 8 if criticality in {"high", "medium"} else 3
    return min(100, max(0, base + exposure_bonus + retention_bonus + criticality_bonus))


def _recommend(label: str, algorithm: str, row: dict[str, Any]) -> str:
    name = _text(algorithm) or "the unspecified algorithm"
    role = _role(_first(row, ("primitive", "cryptographic_role", "role")))
    if label == "UNKNOWN":
        return "Manually review the algorithm, role, and parameters; do not assume it is safe."
    if label == "LEGACY_BROKEN":
        return f"Retire {name}; replace it with a currently approved primitive and rotate affected keys where applicable."
    if label == "HYBRID":
        return "Verify both classical and post-quantum components, protocol binding, and downgrade protection; document an approved transition plan."
    if label == "QUANTUM_VULNERABLE":
        if role == "key_establishment" or any(x in _norm(name) for x in ("ECDH", "ECDHE", "X25519", "X448", "DIFFIEHELLMAN", "FFDHE", "MODP", "DH")):
            return "Plan migration of key establishment to NIST FIPS 203 ML-KEM; assess an approved hybrid transition and interoperability."
        if role == "digital_signature" or any(x in _norm(name) for x in ("ECDSA", "ED25519", "ED448", "EDDSA", "DSA", "RSA")):
            return "Plan migration of signatures to NIST FIPS 204 ML-DSA; assess SLH-DSA where policy and lifecycle needs justify it."
        return "Confirm the cryptographic role, then choose the applicable NIST FIPS 203 key-establishment or FIPS 204 signature migration path."
    if label == "QUANTUM_RESISTANT":
        return "Validate the exact standardized parameter set and implementation, then retain subject to policy and crypto-agility review."
    if label == "SYMMETRIC_OR_HASH":
        return "Retain subject to approved policy, key-strength review, implementation security, and lifecycle monitoring."
    return "Manually review the asset and document the approved next step."


def _rationale(row: dict[str, Any], label: str, score: int) -> str:
    exposure = _yes(_first(row, ("internet_exposed",)))
    exposure_bonus = 25 if exposure is True else 10
    years = _retention_years(row)
    retention_bonus = 20 if years is not None and years >= 10 else 10 if years is not None and years >= 5 else 5
    criticality = _first(row, ("criticality",)).lower()
    criticality_bonus = 15 if criticality == "critical" else 8 if criticality in {"high", "medium"} else 3
    missing = []
    if not _first(row, ("algorithm",)):
        missing.append("algorithm")
    if exposure is None:
        missing.append("internet_exposed")
    if years is None:
        missing.append("data_retention_years")
    if not _first(row, ("criticality",)):
        missing.append("criticality")
    base = {
        "QUANTUM_VULNERABLE": 40, "LEGACY_BROKEN": 35, "UNKNOWN": 20,
        "HYBRID": 15, "QUANTUM_RESISTANT": 5, "SYMMETRIC_OR_HASH": 5,
    }[label]
    raw_total = base + exposure_bonus + retention_bonus + criticality_bonus
    parts = [
        f"label={label}",
        f"score={score}/100",
        f"score_components=base:{base}+exposure:{exposure_bonus}+retention:{retention_bonus}+criticality:{criticality_bonus}={raw_total}; capped_final={score}",
        f"exposure={_first(row, ('internet_exposed',)) or 'unknown'}",
        f"retention={_first(row, ('data_retention_years', 'retention_years', 'retention', 'data_retention')) or 'unknown'}",
        f"criticality={_first(row, ('criticality',)) or 'unspecified'}",
    ]
    if missing:
        parts.append("missing metadata: " + ", ".join(missing))
    return "; ".join(parts)


def _stable_asset_ids(rows: list[dict[str, Any]]) -> list[str]:
    ids = []
    if any("asset_id" in row for row in rows):
        for row in rows:
            value = _text(row.get("asset_id"))
            if not value:
                raise ValueError("Every input row must have a nonblank asset_id")
            ids.append(value)
    elif any("asset_name" in row for row in rows):
        used: set[str] = set()
        counts: dict[str, int] = {}
        for index, row in enumerate(rows, start=1):
            slug = re.sub(r"[^a-z0-9]+", "-", _text(row.get("asset_name")).lower()).strip("-") or f"asset-{index}"
            counts[slug] = counts.get(slug, 0) + 1
            candidate = slug if counts[slug] == 1 else f"{slug}-{counts[slug]}"
            suffix = counts[slug]
            while candidate in used:
                suffix += 1
                candidate = f"{slug}-{suffix}"
            used.add(candidate)
            ids.append(candidate)
    else:
        raise ValueError("Input CSV must include 'asset_id' or 'asset_name'")
    if len(set(ids)) != len(ids):
        raise ValueError("Input asset_id values must be unique")
    return ids


def _dependency_aliases(rows: list[dict[str, Any]], asset_ids: list[str]) -> dict[str, str]:
    """Build a single-pass lookup; duplicate names are intentionally ambiguous."""
    aliases = {asset_id: asset_id for asset_id in asset_ids}
    counts: dict[str, int] = {}
    for row in rows:
        name = _text(row.get("asset_name"))
        if name:
            key = name.casefold()
            counts[key] = counts.get(key, 0) + 1
    for index, row in enumerate(rows):
        name = _text(row.get("asset_name"))
        key = name.casefold()
        if name and counts[key] == 1:
            aliases.setdefault(name, asset_ids[index])
            aliases.setdefault(key, asset_ids[index])
    return aliases


def _dependency_ids(value: Any, known_ids: set[str], aliases: dict[str, str]) -> str:
    raw = _text(value)
    if not raw:
        return ""
    valid = []
    for part in re.split(r"[;,|]", raw):
        item = part.strip()
        resolved = aliases.get(item, "") or aliases.get(item.casefold(), "") or (item if item in known_ids else "")
        if resolved and resolved in known_ids and resolved not in valid:
            valid.append(resolved)
    return ";".join(valid)


def build_predictions(input_csv: str | Path) -> list[dict[str, Any]]:
    rows, _headers = _read_csv(input_csv)
    if not rows:
        raise ValueError("Input CSV must contain at least one data row")
    if not any("algorithm" in row for row in rows):
        raise ValueError("Input CSV must include an 'algorithm' or recognized algorithm-name column")
    asset_ids = _stable_asset_ids(rows)
    known_ids = set(asset_ids)
    dependency_aliases = _dependency_aliases(rows, asset_ids)
    results = []
    for index, row in enumerate(rows):
        algorithm = _first(row, ("algorithm",))
        label = classify_record(row)
        score = _score(row, label)
        exposed = _yes(_first(row, ("internet_exposed",)))
        if label == "UNKNOWN":
            wave = "review"
        elif score >= 75 or (label == "QUANTUM_VULNERABLE" and exposed is True):
            wave = "Wave 1"
        elif label in {"QUANTUM_VULNERABLE", "LEGACY_BROKEN"}:
            wave = "Wave 2"
        else:
            wave = "Wave 3"
        results.append({
            "asset_id": asset_ids[index],
            "predicted_label": label,
            "priority_score": score,
            "priority_rank": 0,
            "recommended_action": _recommend(label, algorithm, row),
            "migration_wave": wave,
            "depends_on": _dependency_ids(_first(row, ("depends_on",)), known_ids, dependency_aliases),
            "rationale": _rationale(row, label, score),
        })
    order = sorted(range(len(results)), key=lambda i: (-results[i]["priority_score"], i))
    for rank, index in enumerate(order, start=1):
        results[index]["priority_rank"] = rank
    return results


def validate_predictions(predictions: list[dict[str, Any]], input_csv: str | Path | None = None) -> None:
    if not predictions:
        raise ValueError("Predictions must contain at least one row")
    for index, row in enumerate(predictions, start=1):
        missing = set(OUTPUT_COLUMNS) - set(row)
        if missing:
            raise ValueError(f"Missing output columns: {sorted(missing)}")
        if not _text(row.get("asset_id")):
            raise ValueError("asset_id cannot be blank")
        if row["predicted_label"] not in LABELS:
            raise ValueError("Invalid predicted_label")
        if row["migration_wave"] not in {"Wave 1", "Wave 2", "Wave 3", "review"}:
            raise ValueError("migration_wave must be Wave 1, Wave 2, Wave 3, or review")
        try:
            score = float(row["priority_score"])
        except (TypeError, ValueError):
            raise ValueError("priority_score must be numeric and between 0 and 100") from None
        if not 0 <= score <= 100:
            raise ValueError("priority_score must be numeric and between 0 and 100")
        if not isinstance(row["priority_rank"], int) or row["priority_rank"] < 1:
            raise ValueError("priority_rank must be a positive integer")
        if not _text(row.get("recommended_action")) or not _text(row.get("rationale")):
            raise ValueError("recommended_action and rationale cannot be blank")
    ids = [str(row["asset_id"]) for row in predictions]
    if len(set(ids)) != len(ids):
        raise ValueError("Output asset_id values must be unique")
    ranks = [row["priority_rank"] for row in predictions]
    if sorted(ranks) != list(range(1, len(predictions) + 1)):
        raise ValueError("priority_rank must be a contiguous ranking from 1 through row count")
    if input_csv is not None:
        source_rows, _ = _read_csv(input_csv)
        expected_ids = _stable_asset_ids(source_rows)
        if len(source_rows) != len(predictions):
            raise ValueError("Output must contain exactly one prediction per input row")
        if expected_ids != ids:
            raise ValueError("Output asset_id order/values must match source IDs or stable generated IDs")
        valid_ids = set(expected_ids)
        for row in predictions:
            dependencies = [item for item in _text(row.get("depends_on")).split(";") if item]
            if any(item not in valid_ids for item in dependencies):
                raise ValueError("depends_on may contain only valid asset IDs")


def write_predictions(path: str | Path, predictions: list[dict[str, Any]]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(predictions)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Input inventory CSV")
    parser.add_argument("--output", required=True, help="Output predictions CSV")
    args = parser.parse_args(argv)
    try:
        predictions = build_predictions(args.input)
        validate_predictions(predictions, args.input)
        write_predictions(args.output, predictions)
    except (OSError, csv.Error, ValueError) as exc:
        parser.error(str(exc))
    print(f"Wrote {len(predictions)} predictions to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
