#!/usr/bin/env python3
"""Exercise the official QFF vetted library APIs; no cryptographic primitive is implemented here."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import secrets
from pathlib import Path


def run_self_tests() -> dict:
    # The official kit uses cryptography's ML-KEM and ML-DSA APIs, plus pqcrypto's
    # SLH-DSA API. Imports stay inside this function so test collection remains
    # possible even when a local environment has not installed the kit packages.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from pqcrypto.kem import ml_kem_768 as pq_kem
    from pqcrypto.sign import slh_dsa_sha2_128s

    message = b"Crypto Inventory & Migration Planner library self-test"

    # ML-KEM-768 round-trip and tamper check using the API specified in the kit.
    kem_private = mlkem.MLKEM768PrivateKey.generate()
    kem_public = kem_private.public_key()
    kem_secret, kem_ciphertext = kem_public.encapsulate()
    kem_round_trip = secrets.compare_digest(kem_secret, kem_private.decapsulate(kem_ciphertext))
    if not kem_round_trip:
        raise RuntimeError("ML-KEM shared-secret round trip failed")

    changed_ct = bytearray(kem_ciphertext)
    changed_ct[0] ^= 1
    try:
        changed_secret = kem_private.decapsulate(bytes(changed_ct))
        kem_tamper_rejected = not secrets.compare_digest(kem_secret, changed_secret)
    except Exception:
        # Some providers reject malformed ciphertexts; others return a different secret.
        kem_tamper_rejected = True
    if not kem_tamper_rejected:
        raise RuntimeError("ML-KEM tampered ciphertext was not detected")

    # Cross-library ML-KEM interoperability (the kit explicitly checks this).
    pq_ciphertext, pq_secret = pq_kem.encaps(kem_public.public_bytes_raw())
    interop_round_trip = secrets.compare_digest(pq_secret, kem_private.decapsulate(pq_ciphertext))
    if not interop_round_trip:
        raise RuntimeError("cryptography <-> pqcrypto ML-KEM interoperability failed")

    # ML-DSA-65 signing and modified-message rejection through cryptography.
    signature_private = mldsa.MLDSA65PrivateKey.generate()
    signature = signature_private.sign(message)
    signature_private.public_key().verify(signature, message)
    try:
        signature_private.public_key().verify(signature, message + b" changed")
        mldsa_tamper_rejected = False
    except InvalidSignature:
        mldsa_tamper_rejected = True
    if not mldsa_tamper_rejected:
        raise RuntimeError("ML-DSA accepted a modified message")

    # SLH-DSA-SHA2-128s signing and verification through pqcrypto.
    slh_public, slh_secret = slh_dsa_sha2_128s.keygen()
    slh_signature = slh_dsa_sha2_128s.sign(slh_secret, message)
    slh_dsa_sha2_128s.verify(slh_public, message, slh_signature)
    try:
        slh_dsa_sha2_128s.verify(slh_public, message + b" changed", slh_signature)
        slh_tamper_rejected = False
    except Exception:
        slh_tamper_rejected = True
    if not slh_tamper_rejected:
        raise RuntimeError("SLH-DSA accepted a modified message")

    # AES-256-GCM authenticated encryption/decryption through cryptography.
    aes_key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(aes_key)
    nonce = secrets.token_bytes(12)
    plaintext = b"library-backed authenticated-encryption self-test"
    ciphertext = aes.encrypt(nonce, plaintext, b"phase2-self-test")
    decrypted = aes.decrypt(nonce, ciphertext, b"phase2-self-test")
    aead_round_trip = secrets.compare_digest(plaintext, decrypted)
    if not aead_round_trip:
        raise RuntimeError("AES-GCM authenticated-encryption round trip failed")

    return {
        "status": "passed",
        "scope": "official-kit library API smoke tests; not a security certification or production key-management design",
        "primitives_implemented_in_project": False,
        "tests": {
            "ml_kem_768_shared_secret_round_trip": kem_round_trip,
            "ml_kem_768_tamper_rejected": kem_tamper_rejected,
            "ml_kem_768_cryptography_pqcrypto_interoperability": interop_round_trip,
            "ml_dsa_65_signature_verification": True,
            "ml_dsa_65_modified_message_rejected": mldsa_tamper_rejected,
            "slh_dsa_sha2_128s_signature_verification": True,
            "slh_dsa_sha2_128s_modified_message_rejected": slh_tamper_rejected,
            "aes_256_gcm_authenticated_encryption_round_trip": aead_round_trip,
        },
        "library_versions": {
            "cryptography": importlib.metadata.version("cryptography"),
            "pqcrypto": importlib.metadata.version("pqcrypto"),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="Optional JSON report path")
    args = parser.parse_args()
    report = run_self_tests()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        print(f"Wrote library self-test report to {target}")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
