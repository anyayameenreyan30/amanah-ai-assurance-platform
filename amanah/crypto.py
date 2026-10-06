"""Ed25519 signing for model artifacts and data manifests.

Keys live in AMANAH_HOME/keys. In production, replace `load_or_create_key` with a
KMS/HSM-backed signer (or Sigstore cosign); the sign/verify interface stays the same.
"""
from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .core import home


def load_or_create_key(name: str) -> Ed25519PrivateKey:
    path = home() / "keys" / f"{name}.pem"
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    path.chmod(0o600)
    (home() / "keys" / f"{name}.pub").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return key


def sign_bytes(key: Ed25519PrivateKey, data: bytes) -> str:
    return base64.b64encode(key.sign(data)).decode()


def verify_bytes(pub: Ed25519PublicKey, signature_b64: str, data: bytes) -> bool:
    try:
        pub.verify(base64.b64decode(signature_b64), data)
        return True
    except (InvalidSignature, ValueError):
        return False
