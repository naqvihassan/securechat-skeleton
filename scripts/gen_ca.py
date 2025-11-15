#!/usr/bin/env python3
"""
Generate Root Certificate Authority (CA)
Creates a self-signed root CA certificate and private key
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import os

def generate_root_ca():
    """Generate a self-signed root CA certificate"""
    
    # Create certs directory if it doesn't exist
    os.makedirs('certs', exist_ok=True)
    
    print("[*] Generating RSA private key for Root CA...")
    # Generate private key (2048-bit RSA)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    print("[*] Creating self-signed root certificate...")
    # Create certificate subject (this is the CA itself)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Information Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])
    
    # Build the certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    
    # Save private key
    print("[*] Saving CA private key to certs/ca_private.key...")
    with open("certs/ca_private.key", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    # Save certificate
    print("[*] Saving CA certificate to certs/ca_cert.pem...")
    with open("certs/ca_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("\n[✓] Root CA generated successfully!")
    print("    Private Key: certs/ca_private.key")
    print("    Certificate: certs/ca_cert.pem")
    print("\n[!] Keep ca_private.key secret and never commit to Git!")
    print("\n[*] To inspect the certificate, run:")
    print("    openssl x509 -in certs/ca_cert.pem -text -noout")

if __name__ == "__main__":
    generate_root_ca()
