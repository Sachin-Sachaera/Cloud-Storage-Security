"""
crypto_utils.py
-----------------
Cryptography module for the Integrated Cloud Security Framework.

Implements a hybrid encryption scheme, which is standard practice for
securing data in cloud environments:

  1. AES-256-GCM  -> fast symmetric encryption of the actual file/data
                      (GCM gives us confidentiality + integrity via an
                      authentication tag, so tampering is detectable).
  2. RSA-2048      -> the AES session key itself is encrypted with the
                      receiver's RSA public key (asymmetric key wrapping),
                      so the symmetric key never travels or is stored in
                      the clear. This is the same pattern used by TLS,
                      PGP, and most real cloud KMS designs.
  3. RSA signatures -> the sender signs a hash of the ciphertext with their
                      RSA private key so the cloud/receiver can verify the
                      data's authenticity and that it was not altered.

Together this gives: Confidentiality (AES) + Key protection (RSA) +
Integrity & Authentication (GCM tag + RSA signature).
"""

import os
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

KEY_DIR = "keys"
AES_KEY_SIZE = 32   # 256-bit AES
NONCE_SIZE = 12      # 96-bit nonce recommended for GCM


# --------------------------------------------------------------------------
# RSA key-pair management (simulates the cloud user's / server's identity)
# --------------------------------------------------------------------------

def generate_rsa_keypair(key_dir=KEY_DIR):
    os.makedirs(key_dir, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    priv_path = os.path.join(key_dir, "rsa_private.pem")
    pub_path = os.path.join(key_dir, "rsa_public.pem")

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    return priv_path, pub_path


def load_rsa_private_key(key_dir=KEY_DIR):
    path = os.path.join(key_dir, "rsa_private.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_rsa_public_key(key_dir=KEY_DIR):
    path = os.path.join(key_dir, "rsa_public.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def ensure_keys_exist(key_dir=KEY_DIR):
    priv_path = os.path.join(key_dir, "rsa_private.pem")
    pub_path = os.path.join(key_dir, "rsa_public.pem")
    if not (os.path.exists(priv_path) and os.path.exists(pub_path)):
        generate_rsa_keypair(key_dir)


# --------------------------------------------------------------------------
# Hybrid encryption: AES-256-GCM (data) + RSA-OAEP (key wrapping) + RSA-PSS (signature)
# --------------------------------------------------------------------------

def encrypt_data(plaintext: bytes, key_dir=KEY_DIR) -> dict:
    ensure_keys_exist(key_dir)
    public_key = load_rsa_public_key(key_dir)
    private_key = load_rsa_private_key(key_dir)  # sender signs with their own key (demo: same identity)

    aes_key = os.urandom(AES_KEY_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # includes GCM auth tag

    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    signature = private_key.sign(
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    envelope = {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "wrapped_key": base64.b64encode(wrapped_key).decode(),
        "signature": base64.b64encode(signature).decode(),
        "algo": "AES-256-GCM + RSA-2048-OAEP + RSA-PSS",
    }
    return envelope


def decrypt_data(envelope: dict, key_dir=KEY_DIR) -> bytes:
    private_key = load_rsa_private_key(key_dir)
    public_key = load_rsa_public_key(key_dir)

    ciphertext = base64.b64decode(envelope["ciphertext"])
    nonce = base64.b64decode(envelope["nonce"])
    wrapped_key = base64.b64decode(envelope["wrapped_key"])
    signature = base64.b64decode(envelope["signature"])

    # 1. Verify signature/integrity BEFORE decrypting
    public_key.verify(
        signature,
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # 2. Unwrap the AES key with RSA private key
    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 3. Decrypt with AES-GCM (also verifies the auth tag -> tamper detection)
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext


def save_envelope(envelope: dict, path: str):
    with open(path, "w") as f:
        json.dump(envelope, f, indent=2)


def load_envelope(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)
