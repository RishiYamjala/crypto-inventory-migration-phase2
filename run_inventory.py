"""Schema-driven cryptographic inventory classification and migration planning.

Usage:
    python run_inventory.py --input inventory.csv --output predictions.csv

This program is deterministic and offline. Unknown, contradictory, or insufficiently
specified records are sent for review rather than being assumed safe.
"""
from __future__ import annotations

import argparse
import math
import re
from pathlib import Path
from typing import Any

import pandas as pd

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

# Names are normalized to uppercase alphanumerics for alias matching.
PQC_MARKERS = (
    "MLKEM", "KYBER", "MLDSA", "DILITHIUM", "SLHDSA", "SPHINCS",
    "FNDSA", "FALCON", "HQC", "LMS", "XMSS",
)
CLASSICAL_MARKERS = (
    "RSA", "ECDH", "ECDSA", "ECDHE", "ED25519", "ED448", "EDDSA",
    "X25519", "X448", "FFDHE", "MODP", "SECP", "P256", "P384", "P521",
    "DIFFIEHELLMAN", "DSA",
)
LEGACY_MARKERS = ("MD5", "SHA1", "3DES", "TDEA", "DESEDE", "RC4", "RC2")
HASH_MARKERS = (
    "SHA256", "SHA384", "SHA512", "SHA3224", "SHA3256", "SHA3384",
    "SHA3512", "SHAKE128", "SHAKE256", "BLAKE2", "BLAKE3",
)
ROLE_ALIASES = {
    "keyestablishment": "key_establishment",
    "keyexchange": "key_establishment",
    "keyagreement": "key_establishment",
    "kem": "key_establishment",
    "signature": "digital_signature",
    "signatures": "digital_signature",
    "signing": "digital_signature",
    "authentication": "digital_signature",
    "publickeyencryption": "public_key_encryption",
    "encryption": "symmetric_encryption",
    "symmetricencryption": "symmetric_encryption",
    "cipher": "symmetric_encryption",
    "hashing": "hash",
    "integrity": "hash",
    "mac": "mac",
    "hmac": "mac",
    "kdf": "kdf",
}
PUBLIC_KEY_ROLES = {"key_establishment", "digital_signature", "public_key_encryption"}
NON_PUBLIC_KEY_ROLES = {"hash", "symmetric_encryption", "mac", "kdf"}


def _text(value: Any) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return str(value).strip()


def _norm(value: Any) -> str:
    return re.sub(r"[^A-Z0-9]", "", _text(value).upper())


def _first(row: pd.Series, names: tuple[str, ...] | list[str], default: str = "") -> str:
    """Return the first nonblank value from known schema/legacy column aliases."""
    for name in names:
        if name in row.index:
            value = _text(row[name])
            if value:
                return value
    return default


def _role(value: Any) -> str:
    raw = _text(value).lower()
    key = re.sub(r"[^a-z0-9]", "", raw)
    return ROLE_ALIASES.get(key, key.replace(" ", "_"))


def classify_algorithm(value: Any) -> str:
    """Classify an algorithm name conservatively; role checks happen in classify_record."""
    s = _norm(value)
    if not s or s in {
        "UNKNOWN", "VENDORMANAGED", "VENDORDEFAULT", "PROPRIETARY",
        "CUSTOM", "CUSTOMXORSCHEME", "N/A", "NA",
    }:
        return "UNKNOWN"

    # Hybrid must be checked before either component family.
    has_pqc = any(marker in s for marker in PQC_MARKERS)
    # DSA is a substring of ML-DSA, FN-DSA, and SLH-DSA; do not mistake
    # those post-quantum names for a classical component.
    classical_markers = tuple(m for m in CLASSICAL_MARKERS if m != "DSA")
    has_classical = any(marker in s for marker in classical_markers)
    if not has_classical and "DSA" in s and not any(x in s for x in ("MLDSA", "FNDSA", "SLHDSA")):
        has_classical = True
    if has_pqc and has_classical:
        return "HYBRID"
    if "HYBRID" in s and has_pqc:
        return "HYBRID"

    # Weak/deprecated algorithms take precedence over generic hash/public-key matches.
    if any(marker in s for marker in LEGACY_MARKERS):
        return "LEGACY_BROKEN"
    if re.fullmatch(r"DES(?:CBC|ECB|CFB|OFB|CTR|XTS)?", s):
        return "LEGACY_BROKEN"

    if has_pqc:
        return "QUANTUM_RESISTANT"

    # RSA signature names such as SHA256withRSA are public-key algorithms, not standalone hashes.
    if any(marker in s for marker in CLASSICAL_MARKERS):
        return "QUANTUM_VULNERABLE"

    if (
        "AES" in s or "CHACHA20" in s or "SM4" in s
        or any(marker in s for marker in HASH_MARKERS)
        or s.startswith(("HMAC", "HKDF", "PBKDF2", "SCRYPT", "ARGON2"))
    ):
        return "SYMMETRIC_OR_HASH"

    return "UNKNOWN"


def _parameter_issue(algorithm: str, params: str) -> bool:
    """Return True for an explicit invalid or contradictory parameter set."""
    a, p = _norm(algorithm), _norm(params)
    if not p:
        return False  # Missing metadata is uncertainty, not proof of invalidity.

    # Detect disagreement between a parameter embedded in the algorithm name and
    # a separately supplied parameter-set column.
    embedded = None
    for pattern in (r"(?:MLKEM|KYBER)(512|768|1024)", r"MLDSA(44|65|87)"):
        match = re.search(pattern, a)
        if match:
            embedded = match.group(1)
            break
    if embedded:
        supplied_digits = re.search(r"(512|768|1024|44|65|87)", p)
        if supplied_digits and supplied_digits.group(1) != embedded:
            return True

    # Recognized standardized parameter-set identifiers.
    checks = (
        (("MLKEM", "KYBER"), {"512", "768", "1024", "MLKEM512", "MLKEM768", "MLKEM1024", "KYBER512", "KYBER768", "KYBER1024"}),
        (("MLDSA", "DILITHIUM"), {"44", "65", "87", "MLDSA44", "MLDSA65", "MLDSA87", "DILITHIUM2", "DILITHIUM3", "DILITHIUM5"}),
        (("SLHDSA", "SPHINCS"), {
            "SHA2128S", "SHA2128F", "SHA2192S", "SHA2192F", "SHA2256S", "SHA2256F",
            "SHAKE128S", "SHAKE128F", "SHAKE192S", "SHAKE192F", "SHAKE256S", "SHAKE256F",
        }),
    )
    for markers, allowed in checks:
        if any(m in a for m in markers):
            return p not in allowed and not any(p.endswith(x) for x in allowed)

    if "AES" in a and p.isdigit():
        return p not in {"128", "192", "256"}
    # RSA and classical key sizes are not restricted to a single valid size here;
    # policy-strength assessment belongs in the risk/action layer.
    return False


def classify_record(row: pd.Series) -> str:
    """Classify using algorithm, primitive/role, and explicit parameter consistency."""
    algorithm = _first(row, ("algorithm",))
    primitive = _role(_first(row, ("primitive", "cryptographic_role", "role")))
    params = _first(row, ("key_size_or_parameter_set", "parameter_set", "key_size"))
    label = classify_algorithm(algorithm)

    if label == "UNKNOWN" or _parameter_issue(algorithm, params):
        return "UNKNOWN"

    # A declared role inconsistent with the algorithm family is not guessed around.
    if primitive in PUBLIC_KEY_ROLES and label in {"SYMMETRIC_OR_HASH", "LEGACY_BROKEN"}:
        return "UNKNOWN"
    if primitive in NON_PUBLIC_KEY_ROLES and label in {
        "QUANTUM_VULNERABLE", "QUANTUM_RESISTANT", "HYBRID"
    }:
        return "UNKNOWN"

    # A bare SHA-256/other hash cannot serve as a digital-signature algorithm.
    norm_alg = _norm(algorithm)
    if primitive == "digital_signature" and any(m in norm_alg for m in HASH_MARKERS):
        if not any(m in norm_alg for m in ("RSA", "ECDSA", "DSA", "MLDSA", "DILITHIUM", "FNDSA", "FALCON")):
            return "UNKNOWN"

    return label


def _retention_years(row: pd.Series) -> float | None:
    raw = _first(row, ("data_retention_years", "retention_years", "retention", "data_retention", "retention_period", "lifespan"))
    if not raw:
        return None
    s = raw.lower()
    if any(x in s for x in ("permanent", "indefinite", "forever")):
        return 10.0
    nums = re.findall(r"\d+(?:\.\d+)?", s)
    if not nums:
        return None
    years = max(float(x) for x in nums)
    if "month" in s:
        years /= 12
    elif "day" in s:
        years /= 365
    elif "year" not in s and years > 100:
        years /= 365
    return max(0.0, years)


def _yes(value: Any) -> bool | None:
    s = _text(value).lower().replace("_", "-")
    if s in {"yes", "true", "1", "internet", "internet-exposed", "internet-facing", "public-facing", "externally-exposed", "external"}:
        return True
    if s in {"no", "false", "0", "internal", "not-exposed", "not-internet-facing", "private"}:
        return False
    return None


def _score(row: pd.Series, label: str) -> int:
    """Transparent 0–100 priority heuristic; unknown metadata adds uncertainty points."""
    base = {
        "QUANTUM_VULNERABLE": 40,
        "LEGACY_BROKEN": 45,
        "UNKNOWN": 25,
        "HYBRID": 15,
        "QUANTUM_RESISTANT": 5,
        "SYMMETRIC_OR_HASH": 5,
    }[label]
    score = base

    exposure = _yes(_first(row, ("internet_exposed", "internet-facing", "exposure")))
    score += 20 if exposure is True else 0 if exposure is False else 10

    years = _retention_years(row)
    if years is None:
        score += 10
    elif years >= 10:
        score += 20
    elif years >= 5:
        score += 15
    elif years >= 1:
        score += 10
    else:
        score += 5

    criticality = _first(row, ("criticality",)).lower()
    score += {"critical": 15, "high": 12, "medium": 8, "low": 3}.get(criticality, 8)

    sensitivity = _first(row, ("data_sensitivity", "sensitivity")).lower()
    score += {"restricted": 10, "confidential": 8, "sensitive": 8, "internal": 4, "public": 0,
              "critical": 10, "high": 8, "medium": 4, "low": 1}.get(sensitivity, 5)

    # Weak classical key sizes are an additional concern.
    alg = _norm(_first(row, ("algorithm",)))
    params = _norm(_first(row, ("key_size_or_parameter_set", "key_size")))
    if "RSA" in alg:
        rsa_bits = re.search(r"(?<!\d)(1024|2048|3072|4096)(?!\d)", params)
        if rsa_bits and int(rsa_bits.group(1)) < 2048:
            score += 15
    if "AES" in alg and ("128" in alg or params == "128"):
        score += 5
    return min(100, max(0, int(score)))


def _recommend(label: str, algorithm: str, row: pd.Series) -> str:
    a = _text(algorithm) or "unspecified algorithm"
    role = _role(_first(row, ("primitive", "cryptographic_role", "role")))
    if label == "UNKNOWN":
        return "Manually review algorithm, cryptographic role, and parameters; do not assume safe"
    if label == "LEGACY_BROKEN":
        return f"Retire {a}; replace with a currently approved primitive and rotate affected keys where applicable"
    if label == "HYBRID":
        return "Verify both components and protocol implementation; document crypto-agility and approved transition plan"
    if label == "QUANTUM_VULNERABLE":
        if role == "key_establishment" or any(x in _norm(a) for x in ("ECDH", "ECDHE", "X25519", "X448", "DIFFIEHELLMAN", "FFDHE", "MODP")):
            return "Plan migration to an approved ML-KEM profile; assess hybrid transition, protocol support, and interoperability"
        if role == "digital_signature" or any(x in _norm(a) for x in ("ECDSA", "ED25519", "ED448", "DSA", "RSA")):
            return "Plan migration to an approved ML-DSA or SLH-DSA profile; validate signature, certificate, and protocol support"
        return "Confirm cryptographic role, then select an approved post-quantum replacement and validate compatibility"
    if label == "QUANTUM_RESISTANT":
        return "Retain subject to parameter-set validation, implementation review, policy approval, and crypto-agility checks"
    if re.search(r"AES[-_ ]?128", a, re.I) or _norm(_first(row, ("key_size_or_parameter_set", "key_size"))) == "128" and "AES" in _norm(a):
        return "Assess upgrade to AES-256 where policy and interoperability permit"
    return "Maintain subject to approved policy, key-strength review, implementation security, and lifecycle monitoring"


def _rationale(row: pd.Series, label: str, score: int) -> str:
    exposure = _yes(_first(row, ("internet_exposed", "internet-facing", "exposure")))
    exposure_text = "internet-exposed" if exposure is True else "not marked internet-exposed" if exposure is False else "exposure unknown"
    years = _retention_years(row)
    retention_text = f"{years:g} years" if years is not None else "retention unknown"
    criticality = _first(row, ("criticality",)) or "unspecified"
    sensitivity = _first(row, ("data_sensitivity", "sensitivity")) or "unspecified"
    missing = []
    if exposure is None:
        missing.append("internet_exposed")
    if years is None:
        missing.append("data_retention_years")
    if not _first(row, ("criticality",)):
        missing.append("criticality")
    if not _first(row, ("data_sensitivity", "sensitivity")):
        missing.append("data_sensitivity")
    uncertainty = f" Missing metadata: {', '.join(missing)}." if missing else ""
    return (
        f"{label}; score {score}/100; {exposure_text}; retention {retention_text}; "
        f"criticality {criticality}; data sensitivity {sensitivity}.{uncertainty}"
    )


def _stable_asset_ids(source: pd.DataFrame) -> list[str]:
    """Use provided IDs, or derive stable readable IDs from asset names when absent."""
    if "asset_id" in source.columns:
        ids = [_text(v) for v in source["asset_id"].tolist()]
        if any(not value for value in ids):
            raise ValueError("Every input row must have a nonblank asset_id")
    elif "asset_name" in source.columns:
        bases = []
        for index, value in enumerate(source["asset_name"].tolist(), start=1):
            slug = re.sub(r"[^a-z0-9]+", "-", _text(value).lower()).strip("-")
            bases.append(slug or f"asset-{index}")
        ids = []
        used: set[str] = set()
        counts: dict[str, int] = {}
        for base in bases:
            counts[base] = counts.get(base, 0) + 1
            candidate = base if counts[base] == 1 else f"{base}-{counts[base]}"
            suffix = counts[base]
            while candidate in used:
                suffix += 1
                candidate = f"{base}-{suffix}"
            used.add(candidate)
            ids.append(candidate)
    else:
        raise ValueError("Input CSV must include 'asset_id' or 'asset_name'")

    if len(set(ids)) != len(ids):
        raise ValueError("Input asset_id values must be unique")
    return ids


def _dependency_ids(value: Any, known_ids: set[str]) -> str:
    """Keep only dependency references that exactly match known asset IDs."""
    raw = _text(value)
    if not raw:
        return ""
    parts = re.split(r"[;,|]", raw)
    valid = []
    for part in parts:
        item = part.strip()
        if item in known_ids and item not in valid:
            valid.append(item)
    return ";".join(valid)


def build_predictions(input_csv: str | Path) -> pd.DataFrame:
    source = pd.read_csv(input_csv, dtype=object, keep_default_na=True)
    if "algorithm" not in source.columns:
        raise ValueError("Input CSV must include an 'algorithm' column")
    asset_ids = _stable_asset_ids(source)
    known_ids = set(asset_ids)

    rows = []
    for row_index, (_, row) in enumerate(source.iterrows()):
        algorithm = _first(row, ("algorithm",))
        label = classify_record(row)
        score = _score(row, label)
        exposed = _yes(_first(row, ("internet_exposed", "internet-facing", "exposure")))
        action = _recommend(label, algorithm, row)

        if label == "UNKNOWN":
            wave = "review"
        elif label == "LEGACY_BROKEN" or (
            label == "QUANTUM_VULNERABLE" and (exposed is True or score >= 65)
        ):
            wave = "1"
        elif label == "QUANTUM_VULNERABLE" or score >= 60:
            wave = "2"
        else:
            wave = "3"

        # Only actual asset IDs supplied in the input can be dependencies.
        depends = _dependency_ids(_first(row, ("depends_on",)), known_ids)
        rationale = _rationale(row, label, score)
        rows.append({
            "asset_id": asset_ids[row_index],
            "predicted_label": label,
            "priority_score": score,
            "recommended_action": action,
            "migration_wave": wave,
            "depends_on": depends,
            "rationale": rationale,
        })

    result = pd.DataFrame(rows, columns=[
        "asset_id", "predicted_label", "priority_score",
        "recommended_action", "migration_wave", "depends_on", "rationale",
    ])
    result["priority_rank"] = result["priority_score"].rank(
        method="first", ascending=False
    ).astype(int)
    return result[OUTPUT_COLUMNS]


def validate_predictions(df: pd.DataFrame, input_csv: str | Path | None = None) -> None:
    missing = set(OUTPUT_COLUMNS) - set(df.columns)
    if missing:
        raise ValueError(f"Missing output columns: {sorted(missing)}")
    if df["asset_id"].isna().any() or df["asset_id"].astype(str).str.strip().eq("").any():
        raise ValueError("asset_id cannot be blank")
    if df["asset_id"].astype(str).duplicated().any():
        raise ValueError("Output asset_id values must be unique")
    if not df["predicted_label"].isin(LABELS).all():
        raise ValueError("Invalid predicted_label")
    if not df["migration_wave"].astype(str).isin({"1", "2", "3", "review"}).all():
        raise ValueError("migration_wave must be 1, 2, 3, or review")
    scores = pd.to_numeric(df["priority_score"], errors="coerce")
    if scores.isna().any() or not scores.between(0, 100).all():
        raise ValueError("priority_score must be numeric and between 0 and 100")
    ranks = pd.to_numeric(df["priority_rank"], errors="coerce")
    if ranks.isna().any() or (ranks < 1).any() or (ranks % 1 != 0).any():
        raise ValueError("priority_rank must be a positive integer")
    if ranks.duplicated().any():
        raise ValueError("priority_rank values must be unique")
    if df["recommended_action"].map(_text).eq("").any():
        raise ValueError("recommended_action cannot be blank")
    if df["rationale"].map(_text).eq("").any():
        raise ValueError("rationale cannot be blank")
    if sorted(ranks.astype(int).tolist()) != list(range(1, len(df) + 1)):
        raise ValueError("priority_rank must be a contiguous ranking from 1 through row count")
    if input_csv is not None:
        source = pd.read_csv(input_csv, dtype=object, keep_default_na=True)
        if len(source) != len(df):
            raise ValueError("Output must contain exactly one prediction per input row")
        expected_ids = _stable_asset_ids(source)
        if expected_ids != df["asset_id"].astype(str).tolist():
            raise ValueError("Output asset_id order/values must match source IDs or stable generated IDs")
        valid_ids = set(expected_ids)
        for dependency_cell in df["depends_on"].fillna("").astype(str):
            dependencies = [item for item in dependency_cell.split(";") if item]
            if any(item not in valid_ids for item in dependencies):
                raise ValueError("depends_on may contain only valid asset IDs")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Input inventory CSV")
    parser.add_argument("--output", required=True, help="Output predictions CSV")
    args = parser.parse_args()
    predictions = build_predictions(args.input)
    validate_predictions(predictions, args.input)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    predictions.to_csv(output, index=False)
    print(f"Wrote {len(predictions)} predictions to {output}")


if __name__ == "__main__":
    main()
