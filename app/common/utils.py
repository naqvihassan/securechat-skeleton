#!/usr/bin/env python3
"""
Common Utility Functions
"""

import os
import hashlib
import base64
import time


def generate_nonce():
    """Generate random 16-byte nonce"""
    return base64.b64encode(os.urandom(16)).decode('utf-8')


def generate_salt():
    """Generate random 16-byte salt for password hashing"""
    return os.urandom(16)


def sha256_hash(*args):
    """
    Concatenate arguments and compute SHA-256 hash
    Returns: hex digest string
    """
    hasher = hashlib.sha256()
    for arg in args:
        if isinstance(arg, str):
            hasher.update(arg.encode('utf-8'))
        elif isinstance(arg, int):
            # Convert int to bytes (big-endian, 8 bytes)
            hasher.update(arg.to_bytes(8, byteorder='big'))
        elif isinstance(arg, bytes):
            hasher.update(arg)
        else:
            hasher.update(str(arg).encode('utf-8'))
    return hasher.hexdigest()


def hash_password(salt, password):
    """
    Compute salted password hash: SHA256(salt || password)
    Returns: hex digest string
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    hasher = hashlib.sha256()
    hasher.update(salt)
    hasher.update(password)
    return hasher.hexdigest()


def now_ms():
    """Get current timestamp in milliseconds"""
    return int(time.time() * 1000)
