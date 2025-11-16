#!/usr/bin/env python3
"""
Transcript and Session Receipt Management
Handles non-repudiation through signed transcripts
"""

import os
import hashlib
import json
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def compute_transcript_hash(transcript_path):
    """
    Compute SHA-256 hash of entire transcript file.
    
    Args:
        transcript_path: Path to transcript file
    
    Returns:
        Hex string of SHA-256 hash
    """
    if not os.path.exists(transcript_path):
        raise FileNotFoundError(f"Transcript not found: {transcript_path}")
    
    sha256 = hashlib.sha256()
    
    with open(transcript_path, 'rb') as f:
        # Read entire file and hash it
        sha256.update(f.read())
    
    return sha256.hexdigest()


def generate_session_receipt(transcript_path, private_key, peer_name, username):
    """
    Generate a SessionReceipt: a signed hash of the transcript.
    
    Format:
    {
        "type": "receipt",
        "peer": "client" or "server",
        "username": "Hassan",
        "first_seq": 1,
        "last_seq": 10,
        "transcript_sha256": "abc123...",
        "sig": "base64_signature"
    }
    
    Args:
        transcript_path: Path to transcript file
        private_key: RSA private key for signing
        peer_name: "client" or "server"
        username: Username for this session
    
    Returns:
        Dictionary containing receipt data
    """
    if not os.path.exists(transcript_path):
        raise FileNotFoundError(f"Transcript not found: {transcript_path}")
    
    # Compute transcript hash
    transcript_hash = compute_transcript_hash(transcript_path)
    
    # Parse transcript to get first/last sequence numbers
    first_seq = None
    last_seq = None
    
    with open(transcript_path, 'r') as f:
        lines = f.readlines()
        
        if lines:
            # First line
            first_line = lines[0].strip()
            if first_line:
                first_seq = int(first_line.split('|')[0])
            
            # Last line
            last_line = lines[-1].strip()
            if last_line:
                last_seq = int(last_line.split('|')[0])
    
    # Create receipt data
    receipt = {
        'type': 'receipt',
        'peer': peer_name,
        'username': username,
        'first_seq': first_seq,
        'last_seq': last_seq,
        'transcript_sha256': transcript_hash
    }
    
    # Sign the transcript hash
    transcript_hash_bytes = transcript_hash.encode('utf-8')
    
    signature = private_key.sign(
        transcript_hash_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    receipt['sig'] = base64.b64encode(signature).decode()
    
    return receipt


def save_receipt(receipt, output_path):
    """
    Save SessionReceipt to JSON file.
    
    Args:
        receipt: Receipt dictionary
        output_path: Path to save receipt
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(receipt, f, indent=2)
    
    print(f"[✓] Receipt saved to: {output_path}")


def verify_receipt(receipt, transcript_path, certificate):
    """
    Verify a SessionReceipt:
    1. Recompute transcript hash
    2. Verify RSA signature using certificate
    
    Args:
        receipt: Receipt dictionary
        transcript_path: Path to transcript file
        certificate: X.509 certificate for verification
    
    Returns:
        (bool, str): (is_valid, message)
    """
    try:
        # 1. Recompute transcript hash
        computed_hash = compute_transcript_hash(transcript_path)
        claimed_hash = receipt['transcript_sha256']
        
        if computed_hash != claimed_hash:
            return False, f"Hash mismatch! Expected: {claimed_hash[:16]}..., Got: {computed_hash[:16]}..."
        
        # 2. Verify signature
        signature = base64.b64decode(receipt['sig'])
        hash_bytes = claimed_hash.encode('utf-8')
        
        public_key = certificate.public_key()
        
        try:
            public_key.verify(
                signature,
                hash_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            return False, f"Signature verification failed: {e}"
        
        return True, "Receipt verified successfully"
        
    except Exception as e:
        return False, f"Verification error: {e}"


def verify_message_in_transcript(transcript_line, sender_cert):
    """
    Verify a single message line from transcript.
    
    Format: seqno|timestamp|ciphertext|signature|fingerprint
    
    Args:
        transcript_line: Single line from transcript
        sender_cert: Certificate of message sender
    
    Returns:
        (bool, str): (is_valid, message)
    """
    try:
        parts = transcript_line.strip().split('|')
        
        if len(parts) != 5:
            return False, "Invalid transcript line format"
        
        seqno, ts, ct_b64, sig_b64, fingerprint = parts
        
        # Recompute hash
        hash_input = f"{seqno}{ts}{ct_b64}".encode()
        expected_hash = hashlib.sha256(hash_input).digest()
        
        # Verify signature
        signature = base64.b64decode(sig_b64)
        public_key = sender_cert.public_key()
        
        try:
            public_key.verify(
                signature,
                expected_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True, f"Message {seqno} verified"
        except Exception:
            return False, f"Message {seqno} signature invalid"
            
    except Exception as e:
        return False, f"Verification error: {e}"


def verify_full_transcript(transcript_path, sender_cert):
    """
    Verify all messages in a transcript file.
    
    Args:
        transcript_path: Path to transcript
        sender_cert: Certificate of sender
    
    Returns:
        (int, int): (total_messages, valid_messages)
    """
    if not os.path.exists(transcript_path):
        raise FileNotFoundError(f"Transcript not found: {transcript_path}")
    
    total = 0
    valid = 0
    
    with open(transcript_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            total += 1
            is_valid, msg = verify_message_in_transcript(line, sender_cert)
            
            if is_valid:
                valid += 1
            else:
                print(f"[!] {msg}")
    
    return total, valid


if __name__ == "__main__":
    print("Transcript and Receipt Management Module")
    print("Use verify_receipt.py for offline verification")
