#!/usr/bin/env python3
"""Exercise vetted library APIs; no cryptographic primitive is implemented here."""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem.ml_kem_768 import decrypt as kem_decapsulate
from pqcrypto.kem.ml_kem_768 import encrypt as kem_encapsulate
from pqcrypto.kem.ml_kem_768 import generate_keypair as kem_generate_keypair
from pqcrypto.sign.ml_dsa_65 import generate_keypair as signature_generate_keypair
from pqcrypto.sign.ml_dsa_65 import sign as signature_sign
from pqcrypto.sign.ml_dsa_65 import verify as signature_verify


def run_self_tests() -> dict:
    # ML-KEM is called through pqcrypto; only status flags are returned, never keys.
    kem_public, kem_secret = kem_generate_keypair()
    kem_ciphertext, shared_secret_sender = kem_encapsulate(kem_public)
    shared_secret_receiver = kem_decapsulate(kem_secret, kem_ciphertext)
    kem_round_trip = secrets.compare_digest(shared_secret_sender, shared_secret_receiver)
    if not kem_round_trip:
        raise RuntimeError("ML-KEM shared-secret round trip failed")

    # ML-DSA key generation, signing, and verification are library calls.
    signing_public, signing_secret = signature_generate_keypair()
    message = b"Crypto Inventory & Migration Planner library self-test"
    signature = signature_sign(signing_secret, message)
    signature_round_trip = bool(signature_verify(signing_public, message, signature))
    if not signature_round_trip:
        raise RuntimeError("ML-DSA signature verification failed")

    # Authenticated symmetric encryption is provided by cryptography's AESGCM.
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
        "scope": "library API smoke test only; not a security certification or production key-management design",
        "primitives_implemented_in_project": False,
        "tests": {
            "ml_kem_768_shared_secret_round_trip": kem_round_trip,
            "ml_dsa_65_signature_verification": signature_round_trip,
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
