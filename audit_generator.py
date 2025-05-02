"""Audit entry generator: builds, encrypts, and signs a single audit record in JSON format."""

import os
import json
import base64
from datetime import datetime, timezone
import argparse

from encryption_utils import (
    encrypt_entry,
    compute_hash_chain,
    load_private_key,
    sign_data,
)

# ---------------------------------------------------------------------------
# Constants and simple file helpers
# ---------------------------------------------------------------------------

PREV_HASH_FILE = "prev_hash.bin"
ZERO_HASH = b"\x00" * 32


def _read_prev_hash() -> bytes:
    """Return previous hash or 32-byte zero block if none exists yet."""
    return open(PREV_HASH_FILE, "rb").read() if os.path.exists(PREV_HASH_FILE) else ZERO_HASH


def _write_prev_hash(hash_bytes: bytes) -> None:
    with open(PREV_HASH_FILE, "wb") as fh:
        fh.write(hash_bytes)


# ---------------------------------------------------------------------------
# Core functionality
# ---------------------------------------------------------------------------


def generate_audit_entry(
    user_id: str,
    patient_id: str,
    action: str,
    aes_key_path: str,
    priv_key_path: str,
    output_path: str,
) -> None:
    """
    Build, encrypt, sign and write one audit entry.
    """
    # --- Load keys ---
    aes_key = open(aes_key_path, "rb").read()
    priv_key = load_private_key(open(priv_key_path, "rb").read())

    # --- Read previous chain hash ---
    prev_hash = _read_prev_hash()

    # --- Build plaintext JSON record ---
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "patientID": patient_id,
        "userID": user_id,
        "action": action,
        "prevHash": base64.b64encode(prev_hash).decode(),
    }
    plaintext = json.dumps(record, separators=(",", ":"), sort_keys=True).encode()

    # --- Encrypt ---
    enc = encrypt_entry(aes_key, plaintext, associated_data=prev_hash)
    new_hash = compute_hash_chain(prev_hash, enc["ciphertext"])

    # --- Sign (IV || ciphertext || tag || prevHash) ---
    data_to_sign = enc["iv"] + enc["ciphertext"] + enc["tag"] + prev_hash
    signature = sign_data(priv_key, data_to_sign)

    # --- Prepare envelope ---
    envelope = {
        "iv": base64.b64encode(enc["iv"]).decode(),
        "ciphertext": base64.b64encode(enc["ciphertext"]).decode(),
        "tag": base64.b64encode(enc["tag"]).decode(),
        "metadata": record,
        "signature": base64.b64encode(signature).decode(),
    }

    # --- Ensure output directory exists and write file ---
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as fh:
        json.dump(envelope, fh, indent=2)

    # --- Persist new chain state ---
    _write_prev_hash(new_hash)
    print(f"Audit entry written ➜ {output_path}")


# ---------------------------------------------------------------------------
# CLI wrapper
# ---------------------------------------------------------------------------


def _main() -> None:
    parser = argparse.ArgumentParser(description="Generate an encrypted, signed audit entry")
    parser.add_argument("--user-id", required=True, help="ID of user performing the action")
    parser.add_argument("--patient-id", required=True, help="ID of patient record accessed")
    parser.add_argument(
        "--action",
        required=True,
        choices=["create", "delete", "update", "query", "print", "copy"],
        help="Type of action logged",
    )
    parser.add_argument("--aes-key", required=True, help="Path to raw 32-byte AES key")
    parser.add_argument("--priv-key", required=True, help="Path to PEM ECDSA private key")
    parser.add_argument("--output", required=True, help="Destination path for envelope JSON")

    # If no arguments at all, just print help and quit gracefully
    if len(os.sys.argv) == 1:
        parser.print_help()
        return

    args = parser.parse_args()
    generate_audit_entry(
        args.user_id,
        args.patient_id,
        args.action,
        args.aes_key,
        args.priv_key,
        args.output,
    )


if __name__ == "__main__":
    _main()