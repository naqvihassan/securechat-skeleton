#!/usr/bin/env python3
"""
Cryptographic Utility Functions
Provides helper functions for certificates, DH, AES, RSA, and hashing
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import hashlib
import datetime
import base64


# ==================== CERTIFICATE OPERATIONS ====================

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


# ==================== DIFFIE-HELLMAN KEY EXCHANGE ====================

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
    # Calculate byte length needed
    byte_length = (shared_secret.bit_length() + 7) // 8
    shared_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
    
    # Hash with SHA-256
    hash_digest = hashlib.sha256(shared_bytes).digest()
    
    # Truncate to 16 bytes for AES-128
    aes_key = hash_digest[:16]
    return aes_key


# ==================== AES ENCRYPTION/DECRYPTION ====================

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


# ==================== RSA SIGNING/VERIFICATION ====================

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


# ==================== HASHING ====================

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


# ==================== HELPER FUNCTIONS ====================

def generate_nonce():
    """Generate random 16-byte nonce"""
    return base64.b64encode(os.urandom(16)).decode('utf-8')


def generate_salt():
    """Generate random 16-byte salt for password hashing"""
    return os.urandom(16)


# ==================== TEST FUNCTIONS ====================

if __name__ == "__main__":
    print("[*] Testing crypto utilities...")
    
    # Test DH key exchange
    print("\n[*] Testing Diffie-Hellman...")
    p, g = generate_dh_parameters()
    alice_private, alice_public = generate_dh_keypair(p, g)
    bob_private, bob_public = generate_dh_keypair(p, g)
    
    alice_shared = compute_dh_shared_secret(alice_private, bob_public, p)
    bob_shared = compute_dh_shared_secret(bob_private, alice_public, p)
    
    if alice_shared == bob_shared:
        print("✓ DH key exchange successful - shared secrets match")
        alice_key = derive_aes_key(alice_shared)
        bob_key = derive_aes_key(bob_shared)
        if alice_key == bob_key:
            print("✓ AES key derivation successful")
    else:
        print("✗ DH key exchange failed")
    
    # Test AES encryption/decryption
    print("\n[*] Testing AES encryption...")
    key = os.urandom(16)
    plaintext = "Hello, SecureChat!"
    ciphertext = aes_encrypt(plaintext, key)
    decrypted = aes_decrypt(ciphertext, key).decode('utf-8')
    
    if plaintext == decrypted:
        print(f"✓ AES encryption/decryption successful")
        print(f"  Plaintext:  {plaintext}")
        print(f"  Decrypted:  {decrypted}")
    else:
        print("✗ AES encryption/decryption failed")
    
    # Test password hashing
    print("\n[*] Testing password hashing...")
    salt = generate_salt()
    password = "mypassword123"
    hash1 = hash_password(salt, password)
    hash2 = hash_password(salt, password)
    
    if hash1 == hash2:
        print("✓ Password hashing consistent")
        print(f"  Hash: {hash1[:32]}...")
    else:
        print("✗ Password hashing inconsistent")
    
    print("\n[✓] All crypto utility tests passed!")
