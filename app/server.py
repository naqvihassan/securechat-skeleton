#!/usr/bin/env python3
"""
Secure Chat Server - Control Plane
Handles certificate exchange, registration, and login
"""

import socket
import json
import sys
import os

from app.crypto.pki import load_certificate, load_private_key, verify_certificate, get_cert_fingerprint
from app.crypto.dh import generate_dh_keypair, compute_dh_shared_secret, derive_aes_key
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import rsa_sign, rsa_verify
from app.common.utils import generate_nonce, generate_salt, hash_password
from app.storage.db import register_user, verify_login, get_user_salt

# Server configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999
BUFFER_SIZE = 8192

# Certificate paths
CA_CERT_PATH = 'certs/ca_cert.pem'
SERVER_CERT_PATH = 'certs/server_cert.pem'
SERVER_KEY_PATH = 'certs/server_private.key'


class SecureChatServer:
    def __init__(self):
        # Load server certificate and private key
        print("[*] Loading server certificate and private key...")
        self.server_cert = load_certificate(SERVER_CERT_PATH)
        self.server_private_key = load_private_key(SERVER_KEY_PATH)
        
        # Load CA certificate for client verification
        print("[*] Loading CA certificate...")
        self.ca_cert = load_certificate(CA_CERT_PATH)
        
        # Server socket
        self.server_socket = None
        
        # Client connection state
        self.client_socket = None
        self.client_cert = None
        self.client_username = None
        self.control_plane_key = None  # Temporary key for registration/login
        
        print("[✓] Server initialized successfully")
    
    def start(self):
        """Start the server and listen for connections"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((SERVER_HOST, SERVER_PORT))
        self.server_socket.listen(1)
        
        print(f"\n[✓] Server listening on {SERVER_HOST}:{SERVER_PORT}")
        print("[*] Waiting for client connection...\n")
        
        try:
            while True:
                self.client_socket, client_address = self.server_socket.accept()
                print(f"[+] Client connected from {client_address}")
                
                try:
                    self.handle_client()
                except Exception as e:
                    print(f"[✗] Error handling client: {e}")
                    import traceback
                    traceback.print_exc()
                finally:
                    if self.client_socket:
                        self.client_socket.close()
                        print("[*] Client disconnected\n")
                    
                    # Reset client state
                    self.client_cert = None
                    self.client_username = None
                    self.control_plane_key = None
                    
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def send_json(self, data):
        """Send JSON message to client"""
        message = json.dumps(data).encode('utf-8')
        self.client_socket.sendall(message + b'\n')
    
    def recv_json(self):
        """Receive JSON message from client"""
        data = b''
        while True:
            chunk = self.client_socket.recv(BUFFER_SIZE)
            if not chunk:
                raise ConnectionError("Client disconnected")
            data += chunk
            if b'\n' in data:
                break
        
        message = data.decode('utf-8').strip()
        return json.loads(message)
    
    def handle_client(self):
        """Handle client connection through control plane"""
        # Step 1: Certificate exchange and verification
        if not self.exchange_certificates():
            print("[✗] Certificate exchange failed")
            return
        
        # Step 2: Temporary DH exchange for control plane encryption
        if not self.control_plane_dh_exchange():
            print("[✗] Control plane DH exchange failed")
            return
        
        # Step 3: Handle registration or login
        self.handle_authentication()
    
    def exchange_certificates(self):
        """Exchange and verify certificates with client"""
        print("[*] Starting certificate exchange...")
        
        try:
            # Receive client hello with certificate
            client_hello = self.recv_json()
            
            if client_hello.get('type') != 'hello':
                print("[✗] Expected 'hello' message")
                self.send_json({'type': 'error', 'message': 'Protocol error'})
                return False
            
            # Load client certificate from PEM string
            from cryptography import x509
            client_cert_pem = client_hello.get('client_cert')
            self.client_cert = x509.load_pem_x509_certificate(client_cert_pem.encode('utf-8'))
            
            print(f"[*] Received client certificate")
            
            # Verify client certificate
            is_valid, message = verify_certificate(self.client_cert, self.ca_cert)
            if not is_valid:
                print(f"[✗] Client certificate verification failed: {message}")
                self.send_json({'type': 'error', 'message': f'BAD_CERT: {message}'})
                return False
            
            print(f"[✓] Client certificate verified: {message}")
            
            # Send server hello with certificate
            from cryptography.hazmat.primitives import serialization
            server_cert_pem = self.server_cert.public_bytes(
                serialization.Encoding.PEM
            ).decode('utf-8')
            
            server_nonce = generate_nonce()
            self.send_json({
                'type': 'server_hello',
                'server_cert': server_cert_pem,
                'nonce': server_nonce
            })
            
            print("[✓] Certificate exchange completed successfully")
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
            # Receive client's DH public values
            dh_client_msg = self.recv_json()
            
            if dh_client_msg.get('type') != 'dh_client':
                print("[✗] Expected 'dh_client' message")
                return False
            
            p = dh_client_msg['p']
            g = dh_client_msg['g']
            client_public = dh_client_msg['A']
            
            print(f"[*] Received client DH public key")
            
            # Generate server's DH keypair
            server_private, server_public = generate_dh_keypair(p, g)
            
            # Send server's DH public key
            self.send_json({
                'type': 'dh_server',
                'B': server_public
            })
            
            # Compute shared secret
            shared_secret = compute_dh_shared_secret(server_private, client_public, p)
            
            # Derive AES key
            self.control_plane_key = derive_aes_key(shared_secret)
            
            print("[✓] Control plane key established")
            return True
            
        except Exception as e:
            print(f"[✗] DH exchange error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def handle_authentication(self):
        """Handle registration or login request"""
        print("[*] Waiting for authentication request...")
        
        try:
            # Receive encrypted authentication request
            auth_msg = self.recv_json()
            
            if auth_msg.get('type') not in ['register', 'login']:
                print("[✗] Expected 'register' or 'login' message")
                self.send_json({'type': 'error', 'message': 'Invalid message type'})
                return
            
            # Decrypt the payload
            encrypted_data = auth_msg.get('data')
            decrypted_bytes = aes_decrypt(encrypted_data, self.control_plane_key)
            decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))
            
            if auth_msg['type'] == 'register':
                self.handle_registration(decrypted_data)
            elif auth_msg['type'] == 'login':
                self.handle_login(decrypted_data)
                
        except Exception as e:
            print(f"[✗] Authentication error: {e}")
            import traceback
            traceback.print_exc()
            self.send_json({'type': 'error', 'message': 'Authentication failed'})
    
    def handle_registration(self, data):
        """Handle user registration"""
        print("[*] Processing registration request...")
        
        try:
            email = data['email']
            username = data['username']
            password = data['password']
            
            # Generate salt and hash password
            salt = generate_salt()
            pwd_hash = hash_password(salt, password)
            
            # Register user in database
            success, message = register_user(email, username, salt, pwd_hash)
            
            if success:
                print(f"[✓] User registered: {username} ({email})")
                # Send encrypted success response
                response = json.dumps({'status': 'success', 'message': message})
                encrypted_response = aes_encrypt(response, self.control_plane_key)
                self.send_json({
                    'type': 'register_response',
                    'data': encrypted_response
                })
            else:
                print(f"[✗] Registration failed: {message}")
                response = json.dumps({'status': 'error', 'message': message})
                encrypted_response = aes_encrypt(response, self.control_plane_key)
                self.send_json({
                    'type': 'register_response',
                    'data': encrypted_response
                })
                
        except Exception as e:
            print(f"[✗] Registration error: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_login(self, data):
        """Handle user login"""
        print("[*] Processing login request...")
        
        try:
            email = data['email']
            password = data['password']
            
            # Get user's salt from database
            salt = get_user_salt(email)
            
            if not salt:
                print(f"[✗] Login failed: email not found")
                response = json.dumps({'status': 'error', 'message': 'Invalid credentials'})
                encrypted_response = aes_encrypt(response, self.control_plane_key)
                self.send_json({
                    'type': 'login_response',
                    'data': encrypted_response
                })
                return
            
            # Hash password with user's salt
            pwd_hash = hash_password(salt, password)
            
            # Verify login
            success, result = verify_login(email, pwd_hash)
            
            if success:
                self.client_username = result  # Store username
                print(f"[✓] User logged in: {result} ({email})")
                response = json.dumps({'status': 'success', 'username': result})
                encrypted_response = aes_encrypt(response, self.control_plane_key)
                self.send_json({
                    'type': 'login_response',
                    'data': encrypted_response
                })
                
                # TODO: Proceed to session key exchange and chat
                print("[*] Ready for session key exchange...")
                
            else:
                print(f"[✗] Login failed: {result}")
                response = json.dumps({'status': 'error', 'message': 'Invalid credentials'})
                encrypted_response = aes_encrypt(response, self.control_plane_key)
                self.send_json({
                    'type': 'login_response',
                    'data': encrypted_response
                })
                
        except Exception as e:
            print(f"[✗] Login error: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    print("=" * 60)
    print("   SECURE CHAT SERVER - Control Plane")
    print("=" * 60)
    
    server = SecureChatServer()
    server.start()
