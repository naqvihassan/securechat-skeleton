#!/usr/bin/env python3
"""
RSA Digital Signatures with SHA-256
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import base64


def rsa_sign(data, private_key):
    """
    Sign data using RSA private key
    Input: data (bytes or string)
    Returns: signature (base64 string)
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Sign using RSA-PSS with SHA-256
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode('utf-8')


def rsa_verify(data, signature_b64, cert):
    """
    Verify RSA signature using certificate's public key
    Returns: True if valid, False otherwise
    """
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        signature = base64.b64decode(signature_b64)
        public_key = cert.public_key()
        
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"[!] Signature verification error: {e}")
        return False
