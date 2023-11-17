"""
Module encryption

Module for encryption operations.

Functions:
    get_random_key(bit_size: int = 128) -> bytes: Generate a random key.
    add_padding(m: bytes, bit_size: int = 128) -> bytes: Add padding to a message.
    remove_padding(m: bytes) -> bytes: Remove padding from a message.
    AES_encrypt(key, plaintext) -> tuple[bytes, bytes]: Encrypt using AES.
    AES_decrypt(key, iv, ciphertext) -> bytes: Decrypt using AES.
"""

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


def get_random_key(bit_size: int = 128) -> bytes:
    """
    Generate a random key.

    Args:
        bit_size (int): Size of the key in bits.

    Returns:
        bytes: Random key.
    """
    return os.urandom(bit_size//8)


def add_padding(m: bytes, bit_size: int = 128) -> bytes:
    """
    Add padding to a message.

    Args:
        m (bytes): Message.
        bit_size (int): Size of the block in bits.

    Returns:
        bytes: Padded message.
    """
    l: int = len(m)  # Length of the message in bytes
    # Number of padding bytes to add
    p: int = (bit_size//8) - (l % (bit_size//8))
    v: bytes = (p - 1).to_bytes()  # Value of the padding bytes
    return m + v*p


def remove_padding(m: bytes) -> bytes:
    """
    Remove padding from a message.

    Args:
        m (bytes): Padded message.

    Returns:
        bytes: Message without padding.
    """
    v: int = m[-1]  # Value of the padding bytes
    p: int = v + 1  # Number of padding bytes to remove
    return m[:-p]


def AES_encrypt(key, plaintext) -> tuple[bytes, bytes]:
    """
    Encrypt using AES.

    Args:
        key: Key for encryption.
        plaintext: Text to encrypt.

    Returns:
        tuple[bytes, bytes]: Initialization Vector (IV) and ciphertext.
    """
    # Generate a random 128-bit IV.
    iv = os.urandom(16)
    # Construct an AES-128-CBC Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()
    # Encrypt the plaintext and get the associated ciphertext.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext)


def AES_decrypt(key, iv, ciphertext) -> bytes:
    """
    Decrypt using AES.

    Args:
        key: Key for decryption.
        iv: Initialization Vector.
        ciphertext: Text to decrypt.

    Returns:
        bytes: Decrypted text.
    """
    # Construct a Cipher object, with the key, iv
    decryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()
    # Decryption gets us the plaintext.
    return decryptor.update(ciphertext) + decryptor.finalize()
