"""Demo file with deliberately weak crypto for QuantumShield tests."""
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec, rsa

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ecc_key = ec.generate_private_key(ec.SECP256R1())
digest = hashlib.md5(b"demo").hexdigest()
ignored = hashlib.sha1(b"demo")  # quantumshield: ignore
