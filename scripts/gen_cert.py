#!/usr/bin/env python3
"""
Generate Server and Client Certificates
Issues RSA X.509 certificates signed by the Root CA
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import sys
import ipaddress

def load_ca():
    """Load CA private key and certificate"""
    print("[*] Loading CA private key and certificate...")
    
    # Load CA private key
    with open("certs/ca_private.key", "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    
    # Load CA certificate
    with open("certs/ca_cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    return ca_private_key, ca_cert


def generate_certificate(entity_type):
    """
    Generate certificate for server or client
    entity_type: 'server' or 'client'
    """
    
    if entity_type not in ['server', 'client']:
        print("[✗] Error: entity_type must be 'server' or 'client'")
        sys.exit(1)
    
    # Load CA
    ca_private_key, ca_cert = load_ca()
    
    print(f"[*] Generating RSA private key for {entity_type}...")
    # Generate entity's private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    print(f"[*] Creating certificate for {entity_type}...")
    
    # Set Common Name based on entity type
    if entity_type == 'server':
        common_name = "localhost"
    else:
        common_name = f"securechat-{entity_type}"
    
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Information Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )
    
    # Add Subject Alternative Name for server
    if entity_type == 'server':
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
    
    # Sign the certificate with CA's private key
    cert = cert_builder.sign(ca_private_key, hashes.SHA256())
    
    # Save private key
    key_filename = f"certs/{entity_type}_private.key"
    print(f"[*] Saving {entity_type} private key to {key_filename}...")
    with open(key_filename, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    # Save certificate
    cert_filename = f"certs/{entity_type}_cert.pem"
    print(f"[*] Saving {entity_type} certificate to {cert_filename}...")
    with open(cert_filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"\n[✓] {entity_type.capitalize()} certificate generated successfully!")
    print(f"    Private Key: {key_filename}")
    print(f"    Certificate: {cert_filename}")
    print(f"\n[*] To inspect the certificate, run:")
    print(f"    openssl x509 -in {cert_filename} -text -noout")
    print(f"\n[*] To verify certificate chain:")
    print(f"    openssl verify -CAfile certs/ca_cert.pem {cert_filename}")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ['server', 'client']:
        print("Usage: python3 gen_cert.py [server|client]")
        sys.exit(1)
    
    entity_type = sys.argv[1]
    generate_certificate(entity_type)
