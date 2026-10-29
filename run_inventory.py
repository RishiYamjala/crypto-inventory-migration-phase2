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
LEGACY_MARKERS = ("MD2", "MD4", "MD5", "SHA1", "3DES", "TDEA", "DESEDE", "RC4", "RC2")
HASH_MARKERS = (
    "SHA224", "SHA256", "SHA384", "SHA512", "SHA3224", "SHA3256", "SHA3384",
    "SHA3512", "SHAKE128", "SHAKE256", "BLAKE2", "BLAKE3", "SM3", "WHIRLPOOL",
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
    "digitalsignature": "digital_signature",
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
    aliases = {
        **ROLE_ALIASES,
        "keyestablishment": "key_establishment",
        "keyencapsulation": "key_establishment",
        "sign": "digital_signature",
        "signaturegeneration": "digital_signature",
        "asymmetricsignature": "digital_signature",
        "publickeyencrypt": "public_key_encryption",
        "symmetriccipher": "symmetric_encryption",
        "blockcipher": "symmetric_encryption",
        "messageauthenticationcode": "mac",
        "keyderivation": "kdf",
        "keyderivationfunction": "kdf",
        "digest": "hash",
        "hashfunction": "hash",
    }
    return aliases.get(key, key)


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
    if re.match(r"^DH(?:\d|$)", s):
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
    if has_classical:
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

    # Embedded standardized parameter identifiers must agree with the inventory field.
    embedded_patterns = (
        (r"(?:MLKEM|KYBER)(512|768|1024)", {"512", "768", "1024"}),
        (r"MLDSA(44|65|87)", {"44", "65", "87"}),
        (r"(?:FNDSA|FALCON)(512|1024)", {"512", "1024"}),
        (r"HQC(128|192|256)", {"128", "192", "256"}),
    )
    for pattern, allowed_digits in embedded_patterns:
        match = re.search(pattern, a)
        if match:
            supplied = re.search(r"(512|768|1024|44|65|87|128|192|256)", p)
            if supplied and supplied.group(1) not in allowed_digits:
                return True
            if supplied and supplied.group(1) != match.group(1):
                return True

    checks = (
        (("MLKEM", "KYBER"), {"512", "768", "1024", "MLKEM512", "MLKEM768", "MLKEM1024", "KYBER512", "KYBER768", "KYBER1024"}),
        (("MLDSA", "DILITHIUM"), {"44", "65", "87", "MLDSA44", "MLDSA65", "MLDSA87", "DILITHIUM2", "DILITHIUM3", "DILITHIUM5"}),
        (("SLHDSA", "SPHINCS"), {
            "SHA2128S", "SHA2128F", "SHA2192S", "SHA2192F", "SHA2256S", "SHA2256F",
            "SHAKE128S", "SHAKE128F", "SHAKE192S", "SHAKE192F", "SHAKE256S", "SHAKE256F",
        }),
        (("FNDSA", "FALCON"), {"512", "1024", "FNDSA512", "FNDSA1024", "FALCON512", "FALCON1024"}),
        (("HQC",), {"128", "192", "256", "HQC128", "HQC192", "HQC256"}),
    )
    for markers, allowed in checks:
        if any(marker in a for marker in markers):
            canonical = re.sub(r"BITS?$", "", p)
            # Exact normalized identifiers only: suffix matching accepted malformed
            # values such as "untrusted-768" as if they were a valid parameter set.
            if canonical not in allowed:
                return True

    if "AES" in a:
        algorithm_bits = re.search(r"AES(128|192|256)", a)
        parameter_bits = re.fullmatch(r"(?:AES)?(?:GCM|CBC|ECB|CTR|XTS|CCM|OCB)?(128|192|256)(?:BITS?)?", p)
        # Reject malformed explicit sizes and disagreement between an embedded
        # AES size and the inventory's explicit parameter field.
        if p.isdigit() and p not in {"128", "192", "256"}:
            return True
        if algorithm_bits and parameter_bits and algorithm_bits.group(1) != parameter_bits.group(1):
            return True
    # Stateful hash-based signature parameter identifiers must be recognizable
    # whenever the inventory explicitly supplies a parameter value.
    if "LMS" in a:
        lms_ok = re.search(r"(?:LMS)?(?:SHA256)?M32H(?:5|10|15|20|25)", p)
        lmots_ok = re.search(r"(?:LMOTS)?(?:SHA256)?N32W(?:1|2|4|8)", p)
        if not (lms_ok or lmots_ok or p in {"5", "10", "15", "20", "25"}):
            return True
    if "XMSS" in a:
        xmss_ok = (
            re.search(r"(?:XMSSMT?)?(?:SHA2|SHAKE)(?:10|16|20|40|60)(?:2|4|6|8)?(?:256|512)", p)
            or re.search(r"(?:XMSSMT?)?(?:SHA256|SHA512)(?:10|16|20|40|60)", p)
            or p in {"10", "16", "20"}
        )
        if not xmss_ok:
            return True
    # RSA and classical key sizes are policy-scored rather than treated as invalid.
    return False

def classify_record(row: pd.Series) -> str:
    """Classify using algorithm, role, and explicit parameter consistency."""
    algorithm = _first(row, ("algorithm",))
    primitive = _role(_first(row, ("primitive", "cryptographic_role", "role")))
    params = _first(row, ("key_size_or_parameter_set", "parameter_set", "key_size"))
    label = classify_algorithm(algorithm)

    if label == "UNKNOWN" or _parameter_issue(algorithm, params):
        return "UNKNOWN"

    norm_alg = _norm(algorithm)
    has_hash = any(marker in norm_alg for marker in HASH_MARKERS) or norm_alg.startswith(("MD2", "MD4", "MD5"))
    has_symmetric_cipher = any(marker in norm_alg for marker in (
        "AES", "CHACHA20", "SM4", "DES", "TDEA", "DESEDE", "RC2", "RC4"
    ))
    has_mac = any(marker in norm_alg for marker in ("HMAC", "CMAC", "GMAC", "POLY1305", "KMAC"))
    has_kdf = norm_alg.startswith(("HKDF", "PBKDF2", "SCRYPT", "ARGON2", "CONCATKDF", "SP800108"))
    has_signature = any(marker in norm_alg for marker in (
        "ECDSA", "ED25519", "ED448", "EDDSA", "MLDSA", "DILITHIUM",
        "FNDSA", "FALCON", "SLHDSA", "SPHINCS", "LMS", "XMSS", "RSA", "DSA"
    )) and not any(marker in norm_alg for marker in ("OAEP", "RSAENCRYPT", "RSAES"))
    has_key_establishment = any(marker in norm_alg for marker in (
        "RSA", "ECDH", "ECDHE", "X25519", "X448", "DIFFIEHELLMAN", "FFDHE", "MODP",
        "MLKEM", "KYBER", "HQC"
    )) or re.match(r"^DH(?:\d|$)", norm_alg) is not None

    if primitive in PUBLIC_KEY_ROLES and label in {"SYMMETRIC_OR_HASH", "LEGACY_BROKEN"}:
        return "UNKNOWN"
    if primitive in NON_PUBLIC_KEY_ROLES and label in {
        "QUANTUM_VULNERABLE", "QUANTUM_RESISTANT", "HYBRID"
    }:
        return "UNKNOWN"
    if primitive == "digital_signature" and not has_signature:
        return "UNKNOWN"
    if primitive == "key_establishment" and not has_key_establishment:
        return "UNKNOWN"
    if primitive == "public_key_encryption" and not any(
        marker in norm_alg for marker in ("RSA", "ELGAMAL", "PAILLIER", "MLKEM", "KYBER")
    ):
        return "UNKNOWN"
    if primitive == "symmetric_encryption" and not has_symmetric_cipher:
        return "UNKNOWN"
    if primitive == "hash" and (not has_hash or has_symmetric_cipher):
        return "UNKNOWN"
    if primitive == "mac" and not has_mac:
        return "UNKNOWN"
    if primitive == "kdf" and not has_kdf:
        return "UNKNOWN"

    return label

def _retention_years(row: pd.Series) -> float | None:
    raw = _first(row, (
        "data_retention_years", "retention_years", "retention", "data_retention",
        "retention_period", "lifespan", "retention_duration", "data_lifetime",
    ))
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
    elif "week" in s:
        years /= 52.1429
    elif "day" in s:
        years /= 365
    elif "year" not in s and years > 100:
        years /= 365
    return max(0.0, years)


def _yes(value: Any) -> bool | None:
    s = _text(value).lower().replace("_", "-")
    if s in {
        "yes", "true", "1", "y", "internet", "internet-exposed", "internet-facing",
        "public-facing", "externally-exposed", "external", "exposed", "public",
    }:
        return True
    if s in {
        "no", "false", "0", "n", "internal", "not-exposed", "not-internet-facing",
        "private", "not internet-facing", "not public-facing", "unexposed",
    }:
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
        rsa_bits = re.search(r"(?<!\d)(512|768|1024|1536|2048|3072|4096)(?!\d)", f"{params} {alg}")
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


def _dependency_ids(value: Any, known_ids: set[str], source: pd.DataFrame, asset_ids: list[str]) -> str:
    """Resolve dependency references to known IDs; discard unresolved or ambiguous names."""
    raw = _text(value)
    if not raw:
        return ""
    aliases: dict[str, str] = {asset_id: asset_id for asset_id in asset_ids}
    if "asset_name" in source.columns:
        names = [_text(value) for value in source["asset_name"].tolist()]
        counts: dict[str, int] = {}
        for name in names:
            if name:
                counts[name] = counts.get(name, 0) + 1
        for index, name in enumerate(names):
            if name and counts[name] == 1 and name not in aliases:
                aliases[name] = asset_ids[index]
    parts = re.split(r"[;,|]", raw)
    valid = []
    for part in parts:
        item = part.strip()
        resolved = aliases.get(item, item if item in known_ids else "")
        if resolved and resolved in known_ids and resolved not in valid:
            valid.append(resolved)
    return ";".join(valid)

def _canonicalize_columns(frame: pd.DataFrame) -> pd.DataFrame:
    """Normalize common organizer/spreadsheet header variants without overwriting data."""
    normalized = {
        re.sub(r"[^a-z0-9]+", "_", str(column).strip().lower()).strip("_"): column
        for column in frame.columns
    }
    aliases = {
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
    # Refuse multiple competing columns for one semantic field instead of
    # silently choosing one (for example both "algorithm" and "Algorithm Name").
    for canonical, candidates in aliases.items():
        originals = [
            column for column in frame.columns
            if re.sub(r"[^a-z0-9]+", "_", str(column).strip().lower()).strip("_") in candidates
        ]
        if len(originals) > 1:
            raise ValueError(
                f"Ambiguous input schema for '{canonical}': multiple columns {originals}"
            )

    rename = {}
    for canonical, candidates in aliases.items():
        if canonical in frame.columns:
            continue
        for candidate in candidates:
            original = normalized.get(candidate)
            if original is not None:
                rename[original] = canonical
                break
    return frame.rename(columns=rename)


def build_predictions(input_csv: str | Path) -> pd.DataFrame:
    source = _canonicalize_columns(pd.read_csv(input_csv, dtype=object, keep_default_na=True))
    if "algorithm" not in source.columns:
        raise ValueError("Input CSV must include an 'algorithm' or recognized algorithm-name column")
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
        depends = _dependency_ids(_first(row, ("depends_on",)), known_ids, source, asset_ids)
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
        source = _canonicalize_columns(pd.read_csv(input_csv, dtype=object, keep_default_na=True))
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
