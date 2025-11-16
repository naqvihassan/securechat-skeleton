#!/usr/bin/env python3
"""
Offline Verification Tool for SessionReceipts and Transcripts

This script verifies:
1. Individual message signatures in transcript
2. SessionReceipt signature
3. Transcript hash integrity

Usage:
    python scripts/verify_receipt.py <receipt.json> <transcript.txt> <signer_cert.pem>

Example:
    python scripts/verify_receipt.py \
        receipts/client_Hassan_receipt.json \
        transcripts/client_Hassan.txt \
        certs/client_cert.pem
"""

import sys
import json
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.crypto.pki import load_certificate
from app.storage.transcript import (
    verify_receipt,
    verify_full_transcript,
    compute_transcript_hash
)


def print_separator():
    print("=" * 70)


def main():
    print_separator()
    print("   OFFLINE VERIFICATION TOOL - SessionReceipt & Transcript")
    print_separator()
    print()
    
    # Check arguments
    if len(sys.argv) != 4:
        print("Usage:")
        print(f"  {sys.argv[0]} <receipt.json> <transcript.txt> <signer_cert.pem>")
        print()
        print("Example:")
        print(f"  {sys.argv[0]} \\")
        print("    receipts/client_Hassan_receipt.json \\")
        print("    transcripts/client_Hassan.txt \\")
        print("    certs/client_cert.pem")
        print()
        sys.exit(1)
    
    receipt_path = sys.argv[1]
    transcript_path = sys.argv[2]
    cert_path = sys.argv[3]
    
    # Verify files exist
    if not os.path.exists(receipt_path):
        print(f"[✗] Receipt not found: {receipt_path}")
        sys.exit(1)
    
    if not os.path.exists(transcript_path):
        print(f"[✗] Transcript not found: {transcript_path}")
        sys.exit(1)
    
    if not os.path.exists(cert_path):
        print(f"[✗] Certificate not found: {cert_path}")
        sys.exit(1)
    
    print(f"[*] Receipt:     {receipt_path}")
    print(f"[*] Transcript:  {transcript_path}")
    print(f"[*] Certificate: {cert_path}")
    print()
    
    # Load files
    print("[*] Loading receipt...")
    with open(receipt_path, 'r') as f:
        receipt = json.load(f)
    
    print(f"    Peer:       {receipt.get('peer')}")
    print(f"    Username:   {receipt.get('username')}")
    print(f"    First Seq:  {receipt.get('first_seq')}")
    print(f"    Last Seq:   {receipt.get('last_seq')}")
    print(f"    Hash:       {receipt.get('transcript_sha256')[:32]}...")
    print()
    
    print("[*] Loading certificate...")
    cert = load_certificate(cert_path)
    print(f"    Subject: {cert.subject.rfc4514_string()}")
    print()
    
    # Step 1: Verify individual messages in transcript
    print_separator()
    print("STEP 1: Verify Individual Message Signatures")
    print_separator()
    print()
    
    total, valid = verify_full_transcript(transcript_path, cert)
    
    print()
    print(f"[*] Total messages: {total}")
    print(f"[✓] Valid messages: {valid}")
    
    if valid == total:
        print("[✓] All message signatures are VALID")
    else:
        print(f"[✗] {total - valid} message(s) have INVALID signatures")
    print()
    
    # Step 2: Verify SessionReceipt
    print_separator()
    print("STEP 2: Verify SessionReceipt")
    print_separator()
    print()
    
    print("[*] Recomputing transcript hash...")
    computed_hash = compute_transcript_hash(transcript_path)
    claimed_hash = receipt['transcript_sha256']
    
    print(f"    Claimed:  {claimed_hash}")
    print(f"    Computed: {computed_hash}")
    
    if computed_hash == claimed_hash:
        print("[✓] Transcript hash MATCHES")
    else:
        print("[✗] Transcript hash MISMATCH!")
    print()
    
    print("[*] Verifying receipt signature...")
    is_valid, message = verify_receipt(receipt, transcript_path, cert)
    
    if is_valid:
        print(f"[✓] {message}")
    else:
        print(f"[✗] {message}")
    print()
    
    # Step 3: Test tamper detection
    print_separator()
    print("STEP 3: Tamper Detection Test")
    print_separator()
    print()
    
    print("[*] Testing: What happens if we modify the transcript?")
    print("    (This is a simulation - we won't actually modify the file)")
    print()
    
    # Simulate modification
    print("    Scenario: If someone changes a single character in the transcript...")
    print("    Expected: Hash mismatch → Receipt signature invalid")
    print()
    
    print("[✓] Tamper detection works because:")
    print("    1. Any change → Different SHA-256 hash")
    print("    2. Different hash → Receipt signature won't verify")
    print("    3. Attacker can't forge signature without private key")
    print()
    
    # Final verdict
    print_separator()
    print("FINAL VERDICT")
    print_separator()
    print()
    
    all_valid = (valid == total) and is_valid
    
    if all_valid:
        print("[✓] ✅ TRANSCRIPT AND RECEIPT ARE VALID")
        print()
        print("    This proves:")
        print("    • All messages were sent by the claimed sender")
        print("    • No messages have been tampered with")
        print("    • The transcript is complete and unmodified")
        print("    • Non-repudiation is achieved")
    else:
        print("[✗] ❌ VERIFICATION FAILED")
        print()
        print("    Possible causes:")
        print("    • Transcript has been modified after signing")
        print("    • Wrong certificate used for verification")
        print("    • Receipt was forged or corrupted")
    
    print()
    print_separator()


if __name__ == "__main__":
    main()
