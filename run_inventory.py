"""Classify cryptographic inventory CSV rows and produce migration plans."""
from __future__ import annotations

import argparse
import math
import re
from pathlib import Path

import pandas as pd

LABELS = {
    "QUANTUM_VULNERABLE",
    "QUANTUM_RESISTANT",
    "HYBRID",
    "SYMMETRIC_OR_HASH",
    "LEGACY_BROKEN",
    "UNKNOWN",
}


def _text(value) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return ""
    return str(value).strip()


def classify_algorithm(value) -> str:
    """Map recognized algorithm names conservatively; blank/ambiguous is UNKNOWN."""
    raw = _text(value)
    if not raw:
        return "UNKNOWN"
    s = re.sub(r"[^A-Z0-9]", "", raw.upper())
    # Detect combined classical + PQC names before matching their components.
    if re.search(r"(X25519|X448|P-?256|P-?384|P-?521|SECP256K1).*(MLKEM|KYBER)|(MLKEM|KYBER).*(X25519|X448|P-?256|P-?384|P-?521|SECP256K1)", s):
        return "HYBRID"
    if "HYBRID" in s and any(x in s for x in ("MLKEM", "MLDSA", "SLHDSA", "KYBER", "DILITHIUM")):
        return "HYBRID"
    if re.search(r"(MLKEM|KYBER)(512|768|1024)?$", s) or re.search(r"(MLDSA|DILITHIUM)(44|65|87)?$", s) or "SLHDSA" in s or "SPHINCS" in s:
        return "QUANTUM_RESISTANT"
    if (any(x in s for x in ("MD5", "SHA1", "3DES", "DESEDE", "RC4"))
            or re.fullmatch(r"DES(?:CBC|ECB|CFB|OFB|CTR|XTS)?", s)):
        return "LEGACY_BROKEN"
    if any(x in s for x in ("AES", "SHA256", "SHA384", "SHA512", "SHA3", "CHACHA20")):
        return "SYMMETRIC_OR_HASH"
    # ML-DSA was classified above; plain DSA is a classical signature family.
    if any(x in s for x in ("RSA", "DSA", "ECDSA", "ECDH", "ED25519", "ED448", "FFDHE", "SECP256K1", "P256", "P384", "P521")) or s.startswith("DH"):
        return "QUANTUM_VULNERABLE"
    return "UNKNOWN"


def _pick(row: pd.Series, names, default=""):
    for name in names:
        if name in row.index:
            value = row[name]
            if _text(value):
                return value
    return default


def _retention_points(value) -> int:
    s = _text(value).lower()
    if not s:
        return 0
    if "permanent" in s or "indefinite" in s or "forever" in s:
        return 20
    nums = [float(n) for n in re.findall(r"\d+(?:\.\d+)?", s)]
    if not nums:
        return 0
    # Ranges use their upper bound as a conservative retention horizon.
    years = max(nums)
    if "month" in s:
        years /= 12
    elif "day" in s:
        years /= 365
    elif "year" not in s and years > 100:
        years /= 365
    return min(20, round(20 * min(years, 10) / 10))


def _yes(value) -> bool:
    # Inventory exports commonly use these exact exposure values. Keep this
    # conservative: do not treat arbitrary text such as "not internet-facing"
    # as a positive exposure signal.
    return _text(value).lower().replace("_", "-") in {
        "yes", "true", "1", "internet", "internet-exposed", "internet-facing",
        "public-facing", "externally-exposed", "external",
    }


def _score(row, label):
    vuln = {"QUANTUM_VULNERABLE": 40, "LEGACY_BROKEN": 35, "UNKNOWN": 20, "HYBRID": 15,
            "QUANTUM_RESISTANT": 5, "SYMMETRIC_OR_HASH": 5}[label]
    exposure = 25 if _yes(_pick(row, ("internet_exposed", "internet-facing", "exposure"))) else 10
    retention = _retention_points(_pick(row, ("retention", "data_retention", "retention_period", "lifespan")))
    criticality = _text(_pick(row, ("criticality", "sensitivity"))).lower()
    crit = 15 if criticality == "critical" else 8 if criticality in {"high", "medium"} else 3
    return min(100, vuln + exposure + retention + crit)


def _recommend(label, algorithm):
    a = _text(algorithm) or "unspecified algorithm"
    if label == "UNKNOWN":
        return "Review asset and identify its algorithm and cryptographic role before migration"
    if label == "QUANTUM_VULNERABLE":
        return f"Replace {a} with an approved PQC equivalent; assess hybrid transition and protocol compatibility"
    if label == "LEGACY_BROKEN":
        return f"Retire {a}; replace with a current approved algorithm and rotate affected keys"
    if label == "HYBRID":
        return "Validate hybrid implementation and plan transition to the approved pure-PQC profile"
    if label == "QUANTUM_RESISTANT":
        return "Retain subject to policy, implementation review, and cryptographic agility checks"
    if re.search(r"AES[-_ ]?128", a, re.I):
        return "Increase symmetric key size to AES-256 where compatibility permits"
    return "Maintain current strength; review key size, implementation, and lifecycle"


def _rationale(label, exposed, retention, criticality):
    exposure_text = "internet-exposed" if exposed else "internal or not marked internet-exposed"
    return (f"{label} classification; {exposure_text}; retention horizon contributes {retention}/20 points; "
            f"criticality recorded as {criticality or 'unspecified'}. Verify source metadata before acting.")


def build_predictions(input_csv: str | Path) -> pd.DataFrame:
    source = pd.read_csv(input_csv, dtype=object, keep_default_na=True)
    if "algorithm" not in source.columns:
        raise ValueError("Input CSV must include an 'algorithm' column")
    out = []
    for _, row in source.iterrows():
        algorithm = _pick(row, ("algorithm",))
        label = classify_algorithm(algorithm)
        exposed = _yes(_pick(row, ("internet_exposed", "internet-facing", "exposure")))
        retention_raw = _pick(row, ("retention", "data_retention", "retention_period", "lifespan"))
        retention_pts = _retention_points(retention_raw)
        criticality = _text(_pick(row, ("criticality", "sensitivity")))
        score = _score(row, label)
        asset_id = _pick(row, ("asset_id", "asset_name", "id"), default="")
        if not asset_id:
            asset_id = str(len(out) + 1)
        action = _recommend(label, algorithm)
        if label == "UNKNOWN":
            wave = "review"
        elif score >= 75 or (exposed and label in {"QUANTUM_VULNERABLE", "LEGACY_BROKEN"}):
            wave = "Wave 1"
        elif label == "QUANTUM_VULNERABLE" or score >= 50:
            wave = "Wave 2"
        elif label == "HYBRID" or (label == "SYMMETRIC_OR_HASH" and re.search(r"AES[-_ ]?128", _text(algorithm), re.I)):
            wave = "Wave 3"
        else:
            wave = "Wave 3"
        depends = "Inventory validation and owner assignment" if label == "UNKNOWN" else (
            "Protocol/vendor compatibility and crypto-agility assessment" if label in {"QUANTUM_VULNERABLE", "HYBRID"}
            else "Key rotation and application test plan" if label == "LEGACY_BROKEN" else "Routine lifecycle review")
        out.append({**row.to_dict(), "asset_id": asset_id, "predicted_label": label,
                    "priority_score": score, "recommended_action": action, "migration_wave": wave,
                    "depends_on": depends,
                    "rationale": _rationale(label, exposed, retention_pts, criticality)})
    result = pd.DataFrame(out)
    result["priority_rank"] = result["priority_score"].rank(method="first", ascending=False).astype(int)
    required = ["asset_id", "predicted_label", "priority_score", "priority_rank", "recommended_action",
                "migration_wave", "depends_on", "rationale"]
    return result[required + [c for c in result.columns if c not in required]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Input inventory CSV (requires an algorithm column)")
    parser.add_argument("--output", required=True, help="Output predictions CSV")
    args = parser.parse_args()
    predictions = build_predictions(args.input)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    predictions.to_csv(args.output, index=False)
    print(f"Wrote {len(predictions)} predictions to {args.output}")


if __name__ == "__main__":
    main()
