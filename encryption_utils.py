"""
Core cryptographic primitives for the Secure Decentralized Audit System.
Provides:
- AES-GCM encryption/decryption
- ECDSA signing/verification
- SHA256-based hash chaining
"""
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature, InvalidTag

# === Symmetric Encryption ===

def generate_aes_key() -> bytes:
    """Generate a new 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_entry(aes_key: bytes, plaintext: bytes, associated_data: bytes = None) -> dict:
    """
    Encrypts plaintext using AES-GCM.
    Returns a dict with:
      - iv: 12-byte initialization vector
      - ciphertext: encrypted data
      - tag: 16-byte authentication tag
    """
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    ct = aesgcm.encrypt(iv, plaintext, associated_data)
    return {
        "iv": iv,
        "ciphertext": ct[:-16],
        "tag": ct[-16:]
    }


def decrypt_entry(aes_key: bytes, iv: bytes, ciphertext: bytes, tag: bytes,
                  associated_data: bytes = None) -> bytes:
    """
    Decrypts AES-GCM ciphertext and verifies authenticity.
    Raises InvalidTag if authentication fails.
    """
    aesgcm = AESGCM(aes_key)
    combined = ciphertext + tag
    return aesgcm.decrypt(iv, combined, associated_data)

# === Asymmetric Signing (ECDSA) ===

def load_private_key(pem_data: bytes, password: bytes = None) -> ec.EllipticCurvePrivateKey:
    """Load an ECDSA private key from PEM-formatted data."""
    return serialization.load_pem_private_key(pem_data, password=password)


def load_public_key(pem_data: bytes) -> ec.EllipticCurvePublicKey:
    """Load an ECDSA public key from PEM-formatted data."""
    return serialization.load_pem_public_key(pem_data)


def sign_data(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """Produce an ECDSA signature (DER-encoded) over data using SHA-256."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_signature(public_key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes) -> bool:
    """Verify an ECDSA-SHA256 signature. Returns True if valid, False otherwise."""
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

# === Hash Chain Utility ===

def compute_hash_chain(prev_hash: bytes, ciphertext: bytes) -> bytes:
    """Compute a SHA-256 hash of prev_hash concatenated with ciphertext."""
    h = hashlib.sha256()
    h.update(prev_hash)
    h.update(ciphertext)
    return h.digest()