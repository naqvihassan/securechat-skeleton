#!/usr/bin/env python3
"""
Secure Chat Client - Phase 5: Data Plane
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
        self.session_key = None  # Session key for encrypted chat
        self.username = None
        
        # Sequence numbers for replay protection
        self.seqno_send = 0
        self.seqno_recv = 0
        
        # Connection state
        self.is_connected = True
        
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
    
    # ==================== PHASE 5: SESSION KEY EXCHANGE ====================
    
    def establish_session_key(self):
        """
        Perform DH key exchange to establish session encryption key.
        This is a NEW DH exchange separate from control plane.
        """
        print("\n[*] Starting session key exchange...")
        
        try:
            # Generate NEW DH parameters for session
            p, g = generate_dh_parameters()
            client_private, client_public = generate_dh_keypair(p, g)
            
            # Send DH session message
            self.send_json({
                'type': 'dh_session_client',
                'p': p,
                'g': g,
                'A': client_public
            })
            
            # Receive server's DH session response
            dh_session_msg = self.recv_json()
            
            if dh_session_msg.get('type') != 'dh_session_server':
                print("[✗] Expected 'dh_session_server' message")
                return False
            
            server_public = dh_session_msg['B']
            
            # Compute shared secret
            shared_secret = compute_dh_shared_secret(client_private, server_public, p)
            
            # Derive session key: K = Trunc_16(SHA256(big_endian(Ks)))
            self.session_key = derive_aes_key(shared_secret)
            
            # Initialize sequence numbers
            self.seqno_send = 0
            self.seqno_recv = 0
            
            print("[✓] Session key established!\n")
            return True
            
        except Exception as e:
            print(f"[✗] Session key exchange failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    # ==================== PHASE 5: ENCRYPTED MESSAGING ====================
    
    def send_message(self, plaintext):
        """
        Encrypt, sign, and send a chat message.
        Format: seqno | ts | ciphertext | signature
        """
        try:
            # Increment sequence number
            self.seqno_send += 1
            seqno = self.seqno_send
            ts = int(time.time() * 1000)  # Unix milliseconds
            
            # --- ENCRYPTION ---
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import padding as sym_padding
            
            # Add PKCS#7 padding
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()
            
            # Encrypt with AES-128 ECB mode
            cipher = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(padded_data) + encryptor.finalize()
            ct_b64 = base64.b64encode(ct).decode()
            
            # --- SIGNATURE ---
            # Compute hash: h = SHA256(seqno || ts || ct)
            hash_input = f"{seqno}{ts}{ct_b64}".encode()
            digest = hashlib.sha256(hash_input).digest()
            
            # Sign with client's private key
            signature = self.client_private_key.sign(
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
            self.send_json(msg)
            
            # --- LOG TO TRANSCRIPT ---
            peer_fingerprint = hashlib.sha256(
                self.server_cert.public_bytes(serialization.Encoding.DER)
            ).hexdigest()[:16]
            
            transcript_line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{peer_fingerprint}\n"
            
            os.makedirs('transcripts', exist_ok=True)
            with open(f"transcripts/client_{self.username}.txt", 'a') as f:
                f.write(transcript_line)
            
        except Exception as e:
            print(f"[✗] Send failed: {e}")
            import traceback
            traceback.print_exc()
    
    def receive_message(self):
        """
        Receive, verify, and decrypt a message.
        Returns plaintext or None if invalid.
        """
        try:
            msg_data = self.recv_json()
            
            if msg_data.get('type') != 'msg':
                return None
            
            seqno = msg_data['seqno']
            ts = msg_data['ts']
            ct_b64 = msg_data['ct']
            sig_b64 = msg_data['sig']
            
            # --- REPLAY PROTECTION ---
            if seqno <= self.seqno_recv:
                print(f"[!] REPLAY detected: seqno {seqno} <= {self.seqno_recv}")
                return None
            
            # --- VERIFY SIGNATURE ---
            hash_input = f"{seqno}{ts}{ct_b64}".encode()
            expected_hash = hashlib.sha256(hash_input).digest()
            
            server_public_key = self.server_cert.public_key()
            signature = base64.b64decode(sig_b64)
            
            try:
                server_public_key.verify(
                    signature,
                    expected_hash,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            except Exception:
                print("[!] SIG_FAIL: Invalid signature from server")
                return None
            
            # --- DECRYPTION ---
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import padding as sym_padding
            
            ct = base64.b64decode(ct_b64)
            cipher = Cipher(algorithms.AES(self.session_key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ct) + decryptor.finalize()
            
            # Remove PKCS#7 padding
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            # Update sequence number
            self.seqno_recv = seqno
            
            # --- LOG TO TRANSCRIPT ---
            peer_fingerprint = hashlib.sha256(
                self.server_cert.public_bytes(serialization.Encoding.DER)
            ).hexdigest()[:16]
            
            transcript_line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{peer_fingerprint}\n"
            
            os.makedirs('transcripts', exist_ok=True)
            with open(f"transcripts/client_{self.username}.txt", 'a') as f:
                f.write(transcript_line)
            
            return plaintext.decode()
            
        except ConnectionError:
            print("\n[!] Server disconnected")
            self.is_connected = False
            return None
        except Exception as e:
            print(f"[!] Receive error: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    # ==================== CHAT LOOP ====================
    
    def chat_loop(self):
        """
        Main chat interface after successful login.
        Uses threading for simultaneous send/receive.
        """
        def receive_thread():
            """Background thread to receive messages"""
            while self.is_connected:
                try:
                    msg = self.receive_message()
                    if msg:
                        print(f"\n[Server] {msg}")
                        print("> ", end="", flush=True)
                except Exception:
                    break
        
        # Start receive thread
        recv_t = threading.Thread(target=receive_thread, daemon=True)
        recv_t.start()
        
        print("\n" + "=" * 60)
        print("   SECURE CHAT SESSION STARTED")
        print("=" * 60)
        print("Type your messages below (or 'quit' to exit):")
        print()
        
        while self.is_connected:
            try:
                user_input = input("> ").strip()
                
                if user_input.lower() == 'quit':
                    print("\n[*] Ending chat session...")
                    break
                
                if user_input:
                    self.send_message(user_input)
                    
            except KeyboardInterrupt:
                print("\n[*] Interrupted by user")
                break
            except Exception as e:
                print(f"\n[!] Error: {e}")
                break
        
        self.is_connected = False
        print("[✓] Chat session ended\n")
    
    # ==================== MAIN FLOW ====================
    
    def run(self):
        """Main client flow"""
        # Connect to server
        if not self.connect():
            return
        
        try:
            # Phase 1: Exchange certificates
            if not self.exchange_certificates():
                print("[✗] Failed to establish secure connection")
                return
            
            # Phase 2: Control plane DH exchange
            if not self.control_plane_dh_exchange():
                print("[✗] Failed to establish control plane encryption")
                return
            
            # Phase 3: Authentication (register or login)
            print("=" * 60)
            choice = input("Choose: (1) Register  (2) Login: ").strip()
            
            authenticated = False
            
            if choice == '1':
                authenticated = self.register()
            elif choice == '2':
                authenticated = self.login()
            else:
                print("[✗] Invalid choice")
                return
            
            if not authenticated:
                print("[✗] Authentication failed")
                return
            
            # Phase 4: Session key exchange
            if not self.establish_session_key():
                print("[✗] Failed to establish session key")
                return
            
            # Phase 5: Start encrypted chat
            self.chat_loop()
            
        except KeyboardInterrupt:
            print("\n[*] Client disconnected")
        except Exception as e:
            print(f"\n[✗] Unexpected error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.client_socket:
                self.client_socket.close()


if __name__ == "__main__":
    print("=" * 60)
    print("   SECURE CHAT CLIENT")
    print("   Phase 5: Control Plane + Data Plane")
    print("=" * 60)
    print()
    
    client = SecureChatClient()
    client.run()
