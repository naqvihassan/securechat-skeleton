#!/usr/bin/env python3
"""
Secure Chat Server - Phase 5: Data Plane
Handles certificate exchange, registration, login, and encrypted chat
"""

import socket
import json
import sys
import os
import hashlib
import base64
import time
import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

from app.crypto.pki import load_certificate, load_private_key, verify_certificate
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
        
        print("[✓] Server initialized successfully")
    
    def start(self):
        """Start the server and listen for connections"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((SERVER_HOST, SERVER_PORT))
        self.server_socket.listen(5)
        
        print(f"\n[✓] Server listening on {SERVER_HOST}:{SERVER_PORT}")
        print("[*] Waiting for client connections...\n")
        
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"[+] Client connected from {client_address}")
                
                # Handle each client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            if self.server_socket:
                self.server_socket.close()
    
    def handle_client(self, client_socket, client_address):
        """Handle individual client connection"""
        # Client-specific state
        client_data = {
            'socket': client_socket,
            'address': client_address,
            'cert': None,
            'username': None,
            'control_plane_key': None,
            'session_key': None,
            'seqno_send': 0,
            'seqno_recv': 0,
            'is_connected': True
        }
        
        try:
            # Phase 1: Certificate exchange
            if not self.exchange_certificates(client_data):
                print(f"[✗] Certificate exchange failed for {client_address}")
                return
            
            # Phase 2: Control plane DH
            if not self.control_plane_dh_exchange(client_data):
                print(f"[✗] Control plane DH failed for {client_address}")
                return
            
            # Phase 3: Authentication
            if not self.handle_authentication(client_data):
                print(f"[✗] Authentication failed for {client_address}")
                return
            
            # Phase 4: Session key exchange
            if not self.session_key_exchange(client_data):
                print(f"[✗] Session key exchange failed for {client_address}")
                return
            
            # Phase 5: Chat session
            self.chat_session(client_data)
            
        except Exception as e:
            print(f"[✗] Error handling client {client_address}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            client_socket.close()
            print(f"[*] Client {client_address} disconnected\n")
    
    def send_json(self, client_socket, data):
        """Send JSON message to client"""
        message = json.dumps(data).encode('utf-8')
        client_socket.sendall(message + b'\n')
    
    def recv_json(self, client_socket):
        """Receive JSON message from client"""
        data = b''
        while True:
            chunk = client_socket.recv(BUFFER_SIZE)
            if not chunk:
                raise ConnectionError("Client disconnected")
            data += chunk
            if b'\n' in data:
                break
        
        message = data.decode('utf-8').strip()
        return json.loads(message)
    
    # ==================== PHASE 1: CERTIFICATE EXCHANGE ====================
    
    def exchange_certificates(self, client_data):
        """Exchange and verify certificates with client"""
        print(f"[*] Starting certificate exchange with {client_data['address']}...")
        
        try:
            # Receive client hello
            client_hello = self.recv_json(client_data['socket'])
            
            if client_hello.get('type') != 'hello':
                print("[✗] Expected 'hello' message")
                self.send_json(client_data['socket'], {'type': 'error', 'message': 'Protocol error'})
                return False
            
            # Load client certificate
            client_cert_pem = client_hello.get('client_cert')
            client_data['cert'] = x509.load_pem_x509_certificate(client_cert_pem.encode('utf-8'))
            
            print(f"[*] Received client certificate")
            
            # Verify client certificate
            is_valid, message = verify_certificate(client_data['cert'], self.ca_cert)
            if not is_valid:
                print(f"[✗] Client certificate verification failed: {message}")
                self.send_json(client_data['socket'], {'type': 'error', 'message': f'BAD_CERT: {message}'})
                return False
            
            print(f"[✓] Client certificate verified: {message}")
            
            # Send server hello
            server_cert_pem = self.server_cert.public_bytes(
                serialization.Encoding.PEM
            ).decode('utf-8')
            
            server_nonce = generate_nonce()
            self.send_json(client_data['socket'], {
                'type': 'server_hello',
                'server_cert': server_cert_pem,
                'nonce': server_nonce
            })
            
            print("[✓] Certificate exchange completed")
            return True
            
        except Exception as e:
            print(f"[✗] Certificate exchange error: {e}")
            return False
    
    # ==================== PHASE 2: CONTROL PLANE DH ====================
    
    def control_plane_dh_exchange(self, client_data):
        """Perform temporary DH exchange for control plane encryption"""
        print(f"[*] Starting control plane DH with {client_data['address']}...")
        
        try:
            # Receive client's DH values
            dh_client_msg = self.recv_json(client_data['socket'])
            
            if dh_client_msg.get('type') != 'dh_client':
                print("[✗] Expected 'dh_client' message")
                return False
            
            p = dh_client_msg['p']
            g = dh_client_msg['g']
            client_public = dh_client_msg['A']
            
            # Generate server's DH keypair
            server_private, server_public = generate_dh_keypair(p, g)
            
            # Send server's DH public key
            self.send_json(client_data['socket'], {
                'type': 'dh_server',
                'B': server_public
            })
            
            # Compute shared secret
            shared_secret = compute_dh_shared_secret(server_private, client_public, p)
            
            # Derive AES key
            client_data['control_plane_key'] = derive_aes_key(shared_secret)
            
            print("[✓] Control plane key established")
            return True
            
        except Exception as e:
            print(f"[✗] DH exchange error: {e}")
            return False
    
    # ==================== PHASE 3: AUTHENTICATION ====================
    
    def handle_authentication(self, client_data):
        """Handle registration or login request"""
        print(f"[*] Waiting for authentication from {client_data['address']}...")
        
        try:
            # Receive encrypted authentication request
            auth_msg = self.recv_json(client_data['socket'])
            
            if auth_msg.get('type') not in ['register', 'login']:
                print("[✗] Expected 'register' or 'login' message")
                return False
            
            # Decrypt the payload
            encrypted_data = auth_msg.get('data')
            decrypted_bytes = aes_decrypt(encrypted_data, client_data['control_plane_key'])
            decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))
            
            if auth_msg['type'] == 'register':
                return self.handle_registration(client_data, decrypted_data)
            elif auth_msg['type'] == 'login':
                return self.handle_login(client_data, decrypted_data)
                
        except Exception as e:
            print(f"[✗] Authentication error: {e}")
            return False
    
    def handle_registration(self, client_data, data):
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
                client_data['username'] = username
                response = json.dumps({'status': 'success', 'message': message})
            else:
                print(f"[✗] Registration failed: {message}")
                response = json.dumps({'status': 'error', 'message': message})
            
            encrypted_response = aes_encrypt(response, client_data['control_plane_key'])
            self.send_json(client_data['socket'], {
                'type': 'register_response',
                'data': encrypted_response
            })
            
            return success
                
        except Exception as e:
            print(f"[✗] Registration error: {e}")
            return False
    
    def handle_login(self, client_data, data):
        """Handle user login"""
        print("[*] Processing login request...")
        
        try:
            email = data['email']
            password = data['password']
            
            # Get user's salt
            salt = get_user_salt(email)
            
            if not salt:
                print(f"[✗] Login failed: email not found")
                response = json.dumps({'status': 'error', 'message': 'Invalid credentials'})
                encrypted_response = aes_encrypt(response, client_data['control_plane_key'])
                self.send_json(client_data['socket'], {
                    'type': 'login_response',
                    'data': encrypted_response
                })
                return False
            
            # Hash password with user's salt
            pwd_hash = hash_password(salt, password)
            
            # Verify login
            success, result = verify_login(email, pwd_hash)
            
            if success:
                client_data['username'] = result
                print(f"[✓] User logged in: {result} ({email})")
                response = json.dumps({'status': 'success', 'username': result})
            else:
                print(f"[✗] Login failed: {result}")
                response = json.dumps({'status': 'error', 'message': 'Invalid credentials'})
            
            encrypted_response = aes_encrypt(response, client_data['control_plane_key'])
            self.send_json(client_data['socket'], {
                'type': 'login_response',
                'data': encrypted_response
            })
            
            return success
                
        except Exception as e:
            print(f"[✗] Login error: {e}")
            return False
    
    # ==================== PHASE 4: SESSION KEY EXCHANGE ====================
    
    def session_key_exchange(self, client_data):
        """
        Perform NEW DH exchange for session encryption key.
        This is separate from control plane DH.
        """
        print(f"[*] Starting session key exchange with {client_data['username']}...")
        
        try:
            # Receive client's session DH values
            dh_session_msg = self.recv_json(client_data['socket'])
            
            if dh_session_msg.get('type') != 'dh_session_client':
                print("[✗] Expected 'dh_session_client' message")
                return False
            
            p = dh_session_msg['p']
            g = dh_session_msg['g']
            client_public = dh_session_msg['A']
            
            # Generate server's session DH keypair
            server_private, server_public = generate_dh_keypair(p, g)
            
            # Send server's session DH public key
            self.send_json(client_data['socket'], {
                'type': 'dh_session_server',
                'B': server_public
            })
            
            # Compute shared secret
            shared_secret = compute_dh_shared_secret(server_private, client_public, p)
            
            # Derive session key
            client_data['session_key'] = derive_aes_key(shared_secret)
            
            # Initialize sequence numbers
            client_data['seqno_send'] = 0
            client_data['seqno_recv'] = 0
            
            print(f"[✓] Session key established for {client_data['username']}")
            return True
            
        except Exception as e:
            print(f"[✗] Session key exchange error: {e}")
            return False
    
    # ==================== PHASE 5: ENCRYPTED CHAT ====================
    
    def send_message(self, client_data, plaintext):
        """
        Encrypt, sign, and send a message to client.
        """
        try:
            # Increment sequence number
            client_data['seqno_send'] += 1
            seqno = client_data['seqno_send']
            ts = int(time.time() * 1000)
            
            # --- ENCRYPTION ---
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import padding as sym_padding
            
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()
            
            cipher = Cipher(algorithms.AES(client_data['session_key']), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(padded_data) + encryptor.finalize()
            ct_b64 = base64.b64encode(ct).decode()
            
            # --- SIGNATURE ---
            hash_input = f"{seqno}{ts}{ct_b64}".encode()
            digest = hashlib.sha256(hash_input).digest()
            
            signature = self.server_private_key.sign(
                digest,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            sig_b64 = base64.b64encode(signature).decode()
            
            # --- SEND MESSAGE ---
            msg = {
                'type': 'msg',
                'seqno': seqno,
                'ts': ts,
                'ct': ct_b64,
                'sig': sig_b64
            }
            self.send_json(client_data['socket'], msg)
            
            # --- LOG TO TRANSCRIPT ---
            peer_fingerprint = hashlib.sha256(
                client_data['cert'].public_bytes(serialization.Encoding.DER)
            ).hexdigest()[:16]
            
            transcript_line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{peer_fingerprint}\n"
            
            os.makedirs('transcripts', exist_ok=True)
            with open(f"transcripts/server_{client_data['username']}.txt", 'a') as f:
                f.write(transcript_line)
            
        except Exception as e:
            print(f"[✗] Send error: {e}")
    
    def receive_message(self, client_data):
        """
        Receive, verify, and decrypt a message from client.
        Returns plaintext or None if invalid.
        """
        try:
            msg_data = self.recv_json(client_data['socket'])
            
            if msg_data.get('type') != 'msg':
                return None
            
            seqno = msg_data['seqno']
            ts = msg_data['ts']
            ct_b64 = msg_data['ct']
            sig_b64 = msg_data['sig']
            
            # --- REPLAY PROTECTION ---
            if seqno <= client_data['seqno_recv']:
                print(f"[!] REPLAY detected from {client_data['username']}: seqno {seqno}")
                return None
            
            # --- VERIFY SIGNATURE ---
            hash_input = f"{seqno}{ts}{ct_b64}".encode()
            expected_hash = hashlib.sha256(hash_input).digest()
            
            client_public_key = client_data['cert'].public_key()
            signature = base64.b64decode(sig_b64)
            
            try:
                client_public_key.verify(
                    signature,
                    expected_hash,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            except Exception:
                print(f"[!] SIG_FAIL from {client_data['username']}")
                return None
            
            # --- DECRYPTION ---
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import padding as sym_padding
            
            ct = base64.b64decode(ct_b64)
            cipher = Cipher(algorithms.AES(client_data['session_key']), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ct) + decryptor.finalize()
            
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            # Update sequence number
            client_data['seqno_recv'] = seqno
            
            # --- LOG TO TRANSCRIPT ---
            peer_fingerprint = hashlib.sha256(
                client_data['cert'].public_bytes(serialization.Encoding.DER)
            ).hexdigest()[:16]
            
            transcript_line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{peer_fingerprint}\n"
            
            os.makedirs('transcripts', exist_ok=True)
            with open(f"transcripts/server_{client_data['username']}.txt", 'a') as f:
                f.write(transcript_line)
            
            return plaintext.decode()
            
        except ConnectionError:
            print(f"[!] Client {client_data['username']} disconnected")
            client_data['is_connected'] = False
            return None
        except Exception as e:
            print(f"[!] Receive error: {e}")
            return None
            
    
    # ==================== PHASE 6: NON-REPUDIATION ====================
    
    def generate_and_save_receipt(self, client_data):
        """
        Generate SessionReceipt at end of chat session.
        Signs the transcript hash and saves receipt.
        """
        print(f"\n[*] Generating SessionReceipt for {client_data['username']}...")
        
        try:
            from app.storage.transcript import generate_session_receipt, save_receipt
            
            transcript_path = f"transcripts/server_{client_data['username']}.txt"
            
            if not os.path.exists(transcript_path):
                print("[!] No transcript found - no messages were exchanged")
                return
            
            # Generate receipt
            receipt = generate_session_receipt(
                transcript_path=transcript_path,
                private_key=self.server_private_key,
                peer_name="server",
                username=client_data['username']
            )
            
            # Save receipt
            receipt_path = f"receipts/server_{client_data['username']}_receipt.json"
            save_receipt(receipt, receipt_path)
            
            print(f"[✓] Server receipt generated")
            print(f"    Transcript hash: {receipt['transcript_sha256'][:32]}...")
            print(f"    Messages: {receipt['first_seq']} to {receipt['last_seq']}")
            
        except Exception as e:
            print(f"[✗] Receipt generation failed: {e}")
            import traceback
            traceback.print_exc()
            
    
    def chat_session(self, client_data):
        """
        Handle encrypted chat session with client.
        """
        print(f"\n[✓] Chat session started with {client_data['username']}")
        print(f"[*] Type messages to send (server-side echo disabled for clarity)")
        
        # Server just receives and echoes messages
        while client_data['is_connected']:
            try:
                # Receive message from client
                msg = self.receive_message(client_data)
                
                if msg:
                    print(f"[{client_data['username']}] {msg}")
                    
                    # Echo back (optional - you can remove this)
                    # self.send_message(client_data, f"Echo: {msg}")
                else:
                    break
                    
            except Exception as e:
                print(f"[!] Chat error: {e}")
                break
        
        print(f"[✓] Chat session ended with {client_data['username']}\n")
        
        # *** PHASE 6: Generate SessionReceipt ***
        self.generate_and_save_receipt(client_data)


if __name__ == "__main__":
    print("=" * 60)
    print("   SECURE CHAT SERVER")
    print("   Phase 5: Control Plane + Data Plane")
    print("=" * 60)
    print()
    
    server = SecureChatServer()
    server.start()
