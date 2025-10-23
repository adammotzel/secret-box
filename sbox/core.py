"""
File encryption and decryption.

General encryption process:

1. User inputs password to use as a symmetric master key.
2. Invoke Argon2 key derivation function (KDF) to derive the encryption key 
   using the provided password, a randomly generated salt, and a randomly 
   generated IV.
3. Encrypt user-defined file with AES-256-GCM using the encryption key.
"""

import os
import json
import tempfile
import shutil

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

from sbox.config import (
    SALT_SIZE,
    IV_SIZE,
    KEY_SIZE,
    TIME_COST,
    MEMORY_COST,
    PARALLELISM,
    ENCRYPTED_FILE,
)


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a symmetric encryption key using Argon2id.

    Parameters
    ----------
    password : str
        The master password input by the user.
    salt : bytes
        A randomly generated salt (16 bytes recommended).

    Returns
    -------
    bytes
        A 32-byte symmetric key derived from the password and salt.
    """

    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=TIME_COST,
        memory_cost=MEMORY_COST,
        parallelism=PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )

    return key


def encrypt_data(data: dict, password: str):
    """
    Encrypt a dictionary of data in memory and write to ENCRYPTED_FILE.

    Parameters
    ----------
    data : dict
        Dictionary of credentials (e.g., {"github": "ghp_..."}).
    password : str
        Master password used for encryption.

    Returns
    -------
    None
    """

    plaintext = json.dumps(data, indent=2).encode("utf-8")

    # Generate salt and IV
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)

    # Derive key using Argon2
    key = derive_key(password, salt)

    # Encrypt using AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    # Package encrypted data as JSON
    encrypted_blob = {
        "salt": salt.hex(),
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
    }

    # create temp file in the same directory as ENCRYPTED_FILE
    temp_dir = os.path.dirname(ENCRYPTED_FILE)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=temp_dir, delete=False
    ) as tmp_file:

        # serialize as json for writing
        json.dump(encrypted_blob, tmp_file)
        # flush Python internal buffers
        tmp_file.flush()
        # for OS to flush buffers to disk
        os.fsync(tmp_file.fileno())
        temp_path = tmp_file.name

    # replace ENCRYPTED_FILE with temp file
    try:
        shutil.move(temp_path, ENCRYPTED_FILE)
    except Exception:
        os.remove(temp_path)
        raise


def decrypt_data(password: str) -> dict:
    """
    Decrypt ENCRYPTED_FILE and return the contents as a Python dictionary.

    Parameters
    ----------
    password : str
        Master password for decryption.

    Returns
    -------
    dict
        Decrypted contents.

    Raises
    ------
    FileNotFoundError
        If secrets.sbox does not yet exist.
    Exception
        If decryption or deserialization fails.
    """

    if not os.path.exists(ENCRYPTED_FILE):
        raise FileNotFoundError("Secret Box not found.")

    # Open secrets.sbox to read encrypted data into memory
    with open(ENCRYPTED_FILE, "r", encoding="utf-8") as f:
        encrypted_blob = json.load(f)

    # Extract encrypted data
    salt = bytes.fromhex(encrypted_blob["salt"])
    iv = bytes.fromhex(encrypted_blob["iv"])
    ciphertext = bytes.fromhex(encrypted_blob["ciphertext"])

    # Derive encryption key, using the password + salt
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    # Decrypt secrets.sbox using encryption key + IV
    try:
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        raise ValueError("Failed to decrypt.") from e


def secure_delete(path):
    """
    Securely delete file from disk.

        1. Overwrite file contents
        2. Delete file

    path : str
        Path to the file.
    """
    if os.path.exists(path):
        with open(path, "ba+", buffering=0) as f:
            length = f.tell()
            f.seek(0)
            f.write(os.urandom(length))
        os.remove(path)
