#!/usr/bin/env python3
"""
PKI Operations - Certificate Loading and Verification
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import datetime


def load_certificate(cert_path):
    """Load X.509 certificate from PEM file"""
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return cert


def load_private_key(key_path):
    """Load RSA private key from PEM file"""
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    return private_key


def verify_certificate(cert, ca_cert):
    """
    Verify certificate signature and validity
    Returns: (is_valid, error_message)
    """
    try:
        # Check if certificate is expired
        now = datetime.datetime.now(datetime.UTC)
        if now < cert.not_valid_before_utc:
            return False, "Certificate not yet valid"
        if now > cert.not_valid_after_utc:
            return False, "Certificate expired"
        
        # Verify signature using CA's public key
        ca_public_key = ca_cert.public_key()
        try:
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        except InvalidSignature:
            return False, "Invalid signature - not signed by trusted CA"
        
        # Verify issuer matches CA subject
        if cert.issuer != ca_cert.subject:
            return False, "Certificate issuer does not match CA subject"
        
        return True, "Certificate valid"
        
    except Exception as e:
        return False, f"Verification error: {str(e)}"


def get_cert_fingerprint(cert):
    """Get SHA256 fingerprint of certificate"""
    fingerprint = cert.fingerprint(hashes.SHA256())
    return fingerprint.hex()


def get_common_name(cert):
    """Extract Common Name (CN) from certificate"""
    for attribute in cert.subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            return attribute.value
    return None
