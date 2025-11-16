#!/usr/bin/env python3
"""
Diffie-Hellman Key Exchange and Key Derivation
"""

import os
import hashlib

# Safe prime (2048-bit) - RFC 3526 Group 14
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)

DH_GENERATOR = 2


def generate_dh_parameters():
    """Return (p, g) for Diffie-Hellman"""
    return DH_PRIME, DH_GENERATOR


def generate_dh_keypair(p, g):
    """
    Generate DH private and public keys
    Returns: (private_key, public_key)
    """
    # Generate random private key (256 bits = 32 bytes)
    private_key = int.from_bytes(os.urandom(32), byteorder='big')
    # Compute public key: g^private mod p
    public_key = pow(g, private_key, p)
    return private_key, public_key


def compute_dh_shared_secret(private_key, peer_public_key, p):
    """
    Compute shared secret: peer_public^private mod p
    Returns: shared_secret (integer)
    """
    shared_secret = pow(peer_public_key, private_key, p)
    return shared_secret


def derive_aes_key(shared_secret):
    """
    Derive AES-128 key from DH shared secret
    K = Trunc16(SHA256(big-endian(Ks)))
    Returns: 16-byte AES key
    """
    # Convert shared secret to big-endian bytes
    byte_length = (shared_secret.bit_length() + 7) // 8
    shared_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
    
    # Hash with SHA-256
    hash_digest = hashlib.sha256(shared_bytes).digest()
    
    # Truncate to 16 bytes for AES-128
    aes_key = hash_digest[:16]
    return aes_key
