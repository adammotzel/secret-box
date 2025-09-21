"""
Unit tests for functions from `sbox.core`.
"""

import os
import tempfile
from unittest import mock

from sbox.core import (
    derive_key,
    encrypt_data,
    decrypt_data,
    secure_delete,
    KEY_SIZE
)


def test_derive_key_is_consistent():
    password = "password"
    salt = b"1234567890abcdef"
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    assert key1 == key2
    assert len(key1) == KEY_SIZE


def test_encrypt_and_decrypt_data():
    password = "secretpassword"
    data = {"github": "ghp_testtoken", "email": "user@example.com"}

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_file = os.path.join(temp_dir, "secret.sbox")
        with mock.patch("sbox.core.ENCRYPTED_FILE", temp_file):
            encrypt_data(data, password)
            assert os.path.exists(temp_file)

            decrypted_data = decrypt_data(password)
            assert decrypted_data == data

            try:
                decrypt_data("wrongpassword")
            except ValueError:
                pass
            else:
                raise AssertionError("ValueError not raised.")


def test_decrypt_raises_file_not_found():
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_file = os.path.join(temp_dir, "doesnotexist.sbox")
        with mock.patch("sbox.core.ENCRYPTED_FILE", temp_file):
            try:
                decrypt_data("any_password")
            except FileNotFoundError:
                pass
            else:
                raise AssertionError("FileNotFoundError not raised.")


def test_secure_delete_removes_file():
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        path = tmp_file.name
        tmp_file.write(b"Sensitive data")
        tmp_file.flush()

    assert os.path.exists(path)

    secure_delete(path)

    assert not os.path.exists(path)
