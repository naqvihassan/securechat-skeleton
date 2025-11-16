#!/usr/bin/env python3
"""
AES-128 Encryption/Decryption with PKCS#7 Padding
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import base64


def aes_encrypt(plaintext, key):
    """
    Encrypt plaintext using AES-128 CBC with PKCS#7 padding
    Returns: base64(IV || ciphertext)
    """
    # Generate random 16-byte IV
    iv = os.urandom(16)
    
    # Create cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad plaintext to block size (16 bytes)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    padded_plaintext = pad(plaintext, AES.block_size)
    
    # Encrypt
    ciphertext = cipher.encrypt(padded_plaintext)
    
    # Return base64(IV || ciphertext)
    return base64.b64encode(iv + ciphertext).decode('utf-8')


def aes_decrypt(ciphertext_b64, key):
    """
    Decrypt AES-128 CBC ciphertext
    Input: base64(IV || ciphertext)
    Returns: plaintext (bytes)
    """
    # Decode base64
    data = base64.b64decode(ciphertext_b64)
    
    # Extract IV (first 16 bytes) and ciphertext
    iv = data[:16]
    ciphertext = data[16:]
    
    # Create cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt and remove padding
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    return plaintext
