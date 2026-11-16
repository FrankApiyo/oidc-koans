"""Fixed keys, so every run signs with the same material.

RSA_1, RSA_2 and EC_1 are the provider's, and RSA_3 is the RS256 key a provider
signing with EC_1 also holds. ATTACKER_RSA is never published.
The PEMs are public test fixtures: never use them for anything real.
"""

from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

_DIR = Path(__file__).resolve().parent / "keys"


def _load(name: str):
    return load_pem_private_key((_DIR / f"{name}.pem").read_bytes(), password=None)


RSA_1 = _load("rsa_1")
RSA_2 = _load("rsa_2")
RSA_3 = _load("rsa_3")
EC_1 = _load("ec_1")
ATTACKER_RSA = _load("attacker_rsa")
HMAC_SECRET = b"toy-hmac-secret-koans-only-32b!!"
