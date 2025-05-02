"""
Client/Server Stub for Secure Audit System (File-based Messaging)

Usage:
  python client_server.py client --user-id USERID --aes-key AES_KEY_FILE --priv-key PRIV_KEY_FILE --patient-id PATIENTID --action ACTION
  python client_server.py server --aes-key AES_KEY_FILE --pub-key PUBLIC_KEY_FILE
  python client_server.py server --query --patient-id PATIENTID
  python client_server.py server --aes-key AES_KEY_FILE --pub-key PUBLIC_KEY_FILE --detect-tampering

Directories:
  messages/      # exchange folder (client writes here, server reads)
  ledger.json    # server-side persistent ledger
  prev_hash.bin  # server-side hash chain state

This stub demonstrates:
- Privacy: encrypts and signs audit entries.
- Queries: server can filter by patientID.
- Immutability: server recomputes hash chain and detects tampering.
"""
import os
import sys
import argparse
import json
import base64
import datetime
import hashlib
import uuid
import traceback
from encryption_utils import encrypt_entry, compute_hash_chain, load_private_key, load_public_key, sign_data, decrypt_entry, verify_signature

# Directory and file constants
MSG_DIR = 'messages'
LEDGER_FILE = 'ledger.json'
PREV_HASH_FILE = 'prev_hash.bin'
ZERO_HASH = b'\x00' * 32

# Ensure messages directory exists
os.makedirs(MSG_DIR, exist_ok=True)

# === Client ===

def client_mode(user_id, aes_key_path, priv_key_path, patient_id, action):
    from audit_generator import generate_audit_entry
    # generate entry in memory
    # for stub, output to messages folder with unique filename
    tmp_output = os.path.join(MSG_DIR, f"{datetime.datetime.utcnow().isoformat()}_{uuid.uuid4().hex}.json")
    # reuse generator
    generate_audit_entry(user_id, patient_id, action,
                         aes_key_path, priv_key_path, tmp_output)
    print(f"Client: wrote message to {tmp_output}")

# === Server Utilities ===

def read_prev_hash():
    if os.path.exists(PREV_HASH_FILE):
        return open(PREV_HASH_FILE, 'rb').read()
    return ZERO_HASH


def write_prev_hash(hash_bytes):
    with open(PREV_HASH_FILE, 'wb') as f:
        f.write(hash_bytes)

# Load ledger
if not os.path.exists(LEDGER_FILE):
    with open(LEDGER_FILE, 'w') as f:
        json.dump([], f)


def server_process(aes_key_path, pub_key_path):
    # Load symmetric key and server public key for signature verification stub
    aes_key = open(aes_key_path, 'rb').read()
    pub_key = load_public_key(open(pub_key_path, 'rb').read())
    # Iterate message files
    ledger = json.load(open(LEDGER_FILE, 'r'))
    files = sorted(os.listdir(MSG_DIR))
    for fname in files:
        path = os.path.join(MSG_DIR, fname)
        try:
            env = json.load(open(path, 'r'))
            iv = base64.b64decode(env['iv'])
            ciphertext = base64.b64decode(env['ciphertext'])
            tag = base64.b64decode(env['tag'])
            signature = base64.b64decode(env['signature'])
            # Use the prevHash that the client embedded
            entry_prev_hash = base64.b64decode(env['metadata']['prevHash'])
            # Verify signature using public key
            data_to_verify = iv + ciphertext + tag + entry_prev_hash
            if not verify_signature(pub_key, data_to_verify, signature):
                raise ValueError('Invalid signature')
            # Decrypt
            plaintext = decrypt_entry(aes_key, iv, ciphertext, tag, associated_data=entry_prev_hash)
            record = json.loads(plaintext)
            # Compute new hash and verify chain
            entry_hash = compute_hash_chain(entry_prev_hash, ciphertext)
            # Append record with metadata
            ledger.append({
                **record,
                'hash': entry_hash.hex(),
                '__iv': env['iv'],
                '__ciphertext': env['ciphertext'],
                '__tag': env['tag'],
                'prevHash': env['metadata']['prevHash']
            })
            # After processing, update file-based prev_hash to entry_hash
            write_prev_hash(entry_hash)
            # Remove message file
            os.remove(path)
            print(f"Server: processed {fname}")
        except Exception as e:
            print(f"Server: failed to process {fname}: {e}")
            traceback.print_exc()
    # Persist updated ledger
    with open(LEDGER_FILE, 'w') as f:
        json.dump(ledger, f, indent=2)


def server_query(patient_id):
    ledger = json.load(open(LEDGER_FILE, 'r'))
    results = [entry for entry in ledger if entry.get('patientID') == patient_id]
    print(json.dumps(results, indent=2))


def server_detect_tampering(aes_key_path):
    # Load AES key to decrypt stored envelope
    aes_key = open(aes_key_path, 'rb').read()
    ledger = json.load(open(LEDGER_FILE, 'r'))
    prev_hash = ZERO_HASH
    tamper_found = False

    for idx, entry in enumerate(ledger):
        # Retrieve raw envelope fields
        iv = base64.b64decode(entry['__iv'])
        ciphertext = base64.b64decode(entry['__ciphertext'])
        tag = base64.b64decode(entry['__tag'])
        embedded_prev = base64.b64decode(entry['prevHash'])

        # Recompute hash chain and compare
        computed_hash = compute_hash_chain(prev_hash, ciphertext).hex()
        if computed_hash != entry['hash']:
            print(f"Tamper detected at entry {idx}: hash mismatch (computed {computed_hash} vs stored {entry['hash']})")
            tamper_found = True

        # Decrypt and inspect metadata
        try:
            plaintext = decrypt_entry(aes_key, iv, ciphertext, tag, associated_data=embedded_prev)
            original = json.loads(plaintext)
        except Exception as e:
            print(f"Tamper detected at entry {idx}: decryption failed ({e})")
            tamper_found = True
            break

        # Compare each metadata field
        for field in ['action','patientID','userID','timestamp','prevHash']:
            if str(original.get(field)) != str(entry.get(field)):
                print(f"Tamper detected at entry {idx}: field '{field}' changed (original={original.get(field)} vs stored={entry.get(field)})")
                tamper_found = True

        if tamper_found:
            break

        # Advance prev_hash for next record
        prev_hash = bytes.fromhex(entry['hash'])

    if not tamper_found:
        print("No tampering detected.")

# === CLI ===

def main():
    parser = argparse.ArgumentParser(description='Client/Server Stub')
    sub = parser.add_subparsers(dest='mode')
    # Client
    pc = sub.add_parser('client')
    pc.add_argument('--user-id', required=True)
    pc.add_argument('--aes-key', required=True)
    pc.add_argument('--priv-key', required=True)
    pc.add_argument('--patient-id', required=True)
    pc.add_argument('--action', required=True, choices=['create','delete','update','query','print','copy'])
    # Server
    ps = sub.add_parser('server')
    ps.add_argument('--aes-key', required=True)
    ps.add_argument('--pub-key', required=True, help='Path to PEM ECDSA public key for signature verification')
    ps.add_argument('--query', action='store_true')
    ps.add_argument('--patient-id')
    ps.add_argument('--detect-tampering', action='store_true')

    args = parser.parse_args()
    if args.mode == 'client':
        client_mode(args.user_id, args.aes_key, args.priv_key, args.patient_id, args.action)
    elif args.mode == 'server':
        if args.query:
            if not args.patient_id:
                print("--patient-id is required for query mode")
            else:
                server_query(args.patient_id)
        elif args.detect_tampering:
            server_detect_tampering(args.aes_key)
        else:
            server_process(args.aes_key, args.pub_key)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
