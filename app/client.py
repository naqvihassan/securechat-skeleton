#!/usr/bin/env python3
"""
Secure Chat Client - Control Plane
Handles certificate exchange, registration, and login
"""

import socket
import json
import sys
import os

from app.crypto.pki import load_certificate, load_private_key, verify_certificate
from app.crypto.dh import generate_dh_parameters, generate_dh_keypair, compute_dh_shared_secret, derive_aes_key
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import rsa_sign, rsa_verify
from app.common.utils import generate_nonce

# Server configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999
BUFFER_SIZE = 8192

# Certificate paths
CA_CERT_PATH = 'certs/ca_cert.pem'
CLIENT_CERT_PATH = 'certs/client_cert.pem'
CLIENT_KEY_PATH = 'certs/client_private.key'


class SecureChatClient:
    def __init__(self):
        # Load client certificate and private key
        print("[*] Loading client certificate and private key...")
        self.client_cert = load_certificate(CLIENT_CERT_PATH)
        self.client_private_key = load_private_key(CLIENT_KEY_PATH)
        
        # Load CA certificate for server verification
        print("[*] Loading CA certificate...")
        self.ca_cert = load_certificate(CA_CERT_PATH)
        
        # Client socket
        self.client_socket = None
        
        # Server state
        self.server_cert = None
        self.control_plane_key = None  # Temporary key for registration/login
        self.username = None
        
        print("[✓] Client initialized successfully\n")
    
    def connect(self):
        """Connect to the server"""
        print(f"[*] Connecting to {SERVER_HOST}:{SERVER_PORT}...")
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            self.client_socket.connect((SERVER_HOST, SERVER_PORT))
            print("[✓] Connected to server\n")
            return True
        except Exception as e:
            print(f"[✗] Connection failed: {e}")
            return False
    
    def send_json(self, data):
        """Send JSON message to server"""
        message = json.dumps(data).encode('utf-8')
        self.client_socket.sendall(message + b'\n')
    
    def recv_json(self):
        """Receive JSON message from server"""
        data = b''
        while True:
            chunk = self.client_socket.recv(BUFFER_SIZE)
            if not chunk:
                raise ConnectionError("Server disconnected")
            data += chunk
            if b'\n' in data:
                break
        
        message = data.decode('utf-8').strip()
        return json.loads(message)
    
    def exchange_certificates(self):
        """Exchange and verify certificates with server"""
        print("[*] Starting certificate exchange...")
        
        try:
            # Send client hello with certificate
            from cryptography.hazmat.primitives import serialization
            client_cert_pem = self.client_cert.public_bytes(
                serialization.Encoding.PEM
            ).decode('utf-8')
            
            client_nonce = generate_nonce()
            self.send_json({
                'type': 'hello',
                'client_cert': client_cert_pem,
                'nonce': client_nonce
            })
            
            # Receive server hello
            server_hello = self.recv_json()
            
            if server_hello.get('type') == 'error':
                print(f"[✗] Server rejected connection: {server_hello.get('message')}")
                return False
            
            if server_hello.get('type') != 'server_hello':
                print("[✗] Unexpected response from server")
                return False
            
            # Load server certificate
            from cryptography import x509
            server_cert_pem = server_hello.get('server_cert')
            self.server_cert = x509.load_pem_x509_certificate(server_cert_pem.encode('utf-8'))
            
            print("[*] Received server certificate")
            
            # Verify server certificate
            is_valid, message = verify_certificate(self.server_cert, self.ca_cert)
            if not is_valid:
                print(f"[✗] Server certificate verification failed: {message}")
                return False
            
            print(f"[✓] Server certificate verified: {message}")
            print("[✓] Certificate exchange completed\n")
            return True
            
        except Exception as e:
            print(f"[✗] Certificate exchange error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def control_plane_dh_exchange(self):
        """Perform temporary DH exchange for control plane encryption"""
        print("[*] Starting control plane DH key exchange...")
        
        try:
            # Generate DH parameters and keypair
            p, g = generate_dh_parameters()
            client_private, client_public = generate_dh_keypair(p, g)
            
            # Send DH public values
            self.send_json({
                'type': 'dh_client',
                'p': p,
                'g': g,
                'A': client_public
            })
            
            # Receive server's DH public key
            dh_server_msg = self.recv_json()
            
            if dh_server_msg.get('type') != 'dh_server':
                print("[✗] Expected 'dh_server' message")
                return False
            
            server_public = dh_server_msg['B']
            
            # Compute shared secret
            shared_secret = compute_dh_shared_secret(client_private, server_public, p)
            
            # Derive AES key
            self.control_plane_key = derive_aes_key(shared_secret)
            
            print("[✓] Control plane key established\n")
            return True
            
        except Exception as e:
            print(f"[✗] DH exchange error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def register(self):
        """Register a new user"""
        print("=" * 60)
        print("   USER REGISTRATION")
        print("=" * 60)
        
        email = input("Email: ").strip()
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        
        try:
            # Prepare registration data
            reg_data = {
                'email': email,
                'username': username,
                'password': password
            }
            
            # Encrypt with control plane key
            encrypted_data = aes_encrypt(json.dumps(reg_data), self.control_plane_key)
            
            # Send registration request
            self.send_json({
                'type': 'register',
                'data': encrypted_data
            })
            
            # Receive response
            response = self.recv_json()
            
            if response.get('type') == 'register_response':
                # Decrypt response
                decrypted_bytes = aes_decrypt(response['data'], self.control_plane_key)
                result = json.loads(decrypted_bytes.decode('utf-8'))
                
                if result['status'] == 'success':
                    print(f"\n[✓] {result['message']}")
                    return True
                else:
                    print(f"\n[✗] Registration failed: {result['message']}")
                    return False
            else:
                print("[✗] Unexpected response")
                return False
                
        except Exception as e:
            print(f"[✗] Registration error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def login(self):
        """Login existing user"""
        print("=" * 60)
        print("   USER LOGIN")
        print("=" * 60)
        
        email = input("Email: ").strip()
        password = input("Password: ").strip()
        
        try:
            # Prepare login data
            login_data = {
                'email': email,
                'password': password
            }
            
            # Encrypt with control plane key
            encrypted_data = aes_encrypt(json.dumps(login_data), self.control_plane_key)
            
            # Send login request
            self.send_json({
                'type': 'login',
                'data': encrypted_data
            })
            
            # Receive response
            response = self.recv_json()
            
            if response.get('type') == 'login_response':
                # Decrypt response
                decrypted_bytes = aes_decrypt(response['data'], self.control_plane_key)
                result = json.loads(decrypted_bytes.decode('utf-8'))
                
                if result['status'] == 'success':
                    self.username = result['username']
                    print(f"\n[✓] Login successful! Welcome, {self.username}")
                    return True
                else:
                    print(f"\n[✗] Login failed: {result['message']}")
                    return False
            else:
                print("[✗] Unexpected response")
                return False
                
        except Exception as e:
            print(f"[✗] Login error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run(self):
        """Main client flow"""
        # Connect to server
        if not self.connect():
            return
        
        try:
            # Exchange certificates
            if not self.exchange_certificates():
                print("[✗] Failed to establish secure connection")
                return
            
            # Control plane DH exchange
            if not self.control_plane_dh_exchange():
                print("[✗] Failed to establish control plane encryption")
                return
            
            # Ask user: register or login
            print("=" * 60)
            choice = input("Choose: (1) Register  (2) Login: ").strip()
            
            if choice == '1':
                self.register()
            elif choice == '2':
                if self.login():
                    # TODO: Proceed to session key exchange and chat
                    print("\n[*] Control plane complete. Chat session coming soon...")
            else:
                print("[✗] Invalid choice")
            
        except KeyboardInterrupt:
            print("\n[*] Client disconnected")
        finally:
            if self.client_socket:
                self.client_socket.close()


if __name__ == "__main__":
    print("=" * 60)
    print("   SECURE CHAT CLIENT - Control Plane")
    print("=" * 60)
    print()
    
    client = SecureChatClient()
    client.run()
