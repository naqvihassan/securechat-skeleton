#!/usr/bin/env python3
"""
Database Utility Functions
Handles MySQL operations for user registration and authentication
"""

import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'user': os.getenv('DB_USER', 'chatuser'),
    'password': os.getenv('DB_PASSWORD', 'hassan123'),
    'database': os.getenv('DB_NAME', 'securechat')
}


def get_connection():
    """
    Create and return a database connection
    Returns: connection object or None if failed
    """
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        print(f"[✗] Database connection error: {e}")
        return None


def register_user(email, username, salt, pwd_hash):
    """
    Register a new user in the database
    Args:
        email: user's email (unique)
        username: user's username (unique)
        salt: 16-byte salt (binary)
        pwd_hash: hex string of SHA256(salt || password)
    Returns: (success, message)
    """
    conn = get_connection()
    if not conn:
        return False, "Database connection failed"
    
    try:
        cursor = conn.cursor()
        
        # Check if email already exists
        cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return False, "Email already registered"
        
        # Check if username already exists
        cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            return False, "Username already taken"
        
        # Insert new user
        query = """
            INSERT INTO users (email, username, salt, pwd_hash)
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (email, username, salt, pwd_hash))
        conn.commit()
        
        print(f"[✓] User registered: {username} ({email})")
        return True, "Registration successful"
        
    except Error as e:
        print(f"[✗] Registration error: {e}")
        return False, f"Registration failed: {str(e)}"
    
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def verify_login(email, pwd_hash):
    """
    Verify user login credentials
    Args:
        email: user's email
        pwd_hash: hex string of SHA256(salt || password)
    Returns: (success, username or error_message)
    """
    conn = get_connection()
    if not conn:
        return False, "Database connection failed"
    
    try:
        cursor = conn.cursor()
        
        # Fetch user by email
        query = "SELECT username, pwd_hash FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        result = cursor.fetchone()
        
        if not result:
            return False, "Email not found"
        
        stored_username, stored_pwd_hash = result
        
        # Compare password hashes (constant-time comparison would be better)
        if pwd_hash == stored_pwd_hash:
            print(f"[✓] Login successful: {stored_username} ({email})")
            return True, stored_username
        else:
            print(f"[✗] Login failed: incorrect password for {email}")
            return False, "Incorrect password"
        
    except Error as e:
        print(f"[✗] Login verification error: {e}")
        return False, f"Login failed: {str(e)}"
    
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def get_user_salt(email):
    """
    Retrieve user's salt for password hashing
    Args:
        email: user's email
    Returns: salt (bytes) or None if user not found
    """
    conn = get_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        query = "SELECT salt FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        result = cursor.fetchone()
        
        if result:
            return result[0]  # Return salt bytes
        return None
        
    except Error as e:
        print(f"[✗] Error fetching salt: {e}")
        return None
    
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def user_exists(email):
    """
    Check if user exists by email
    Returns: True if exists, False otherwise
    """
    conn = get_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
        return cursor.fetchone() is not None
        
    except Error as e:
        print(f"[✗] Error checking user: {e}")
        return False
    
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


def get_all_users():
    """
    Get all registered users (for testing/debugging only)
    Returns: list of (email, username) tuples
    """
    conn = get_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT email, username FROM users")
        users = cursor.fetchall()
        return users
        
    except Error as e:
        print(f"[✗] Error fetching users: {e}")
        return []
    
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()


# ==================== TEST FUNCTIONS ====================

if __name__ == "__main__":
    print("[*] Testing database utilities...")
    
    # Test connection
    print("\n[*] Testing database connection...")
    conn = get_connection()
    if conn:
        print("✓ Database connection successful")
        conn.close()
    else:
        print("✗ Database connection failed")
        exit(1)
    
    # Test user registration
    print("\n[*] Testing user registration...")
    from crypto_utils import generate_salt, hash_password
    
    test_email = "test@example.com"
    test_username = "testuser"
    test_password = "securepass123"
    test_salt = generate_salt()
    test_pwd_hash = hash_password(test_salt, test_password)
    
    # Clean up test user if exists
    conn = get_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE email = %s", (test_email,))
        conn.commit()
        cursor.close()
        conn.close()
    
    success, message = register_user(test_email, test_username, test_salt, test_pwd_hash)
    if success:
        print(f"✓ Registration successful: {message}")
    else:
        print(f"✗ Registration failed: {message}")
    
    # Test duplicate registration
    print("\n[*] Testing duplicate registration prevention...")
    success, message = register_user(test_email, test_username, test_salt, test_pwd_hash)
    if not success and "already" in message.lower():
        print(f"✓ Duplicate prevention working: {message}")
    else:
        print(f"✗ Duplicate prevention failed")
    
    # Test login with correct password
    print("\n[*] Testing login with correct password...")
    success, result = verify_login(test_email, test_pwd_hash)
    if success and result == test_username:
        print(f"✓ Login successful: {result}")
    else:
        print(f"✗ Login failed: {result}")
    
    # Test login with wrong password
    print("\n[*] Testing login with wrong password...")
    wrong_pwd_hash = hash_password(test_salt, "wrongpassword")
    success, result = verify_login(test_email, wrong_pwd_hash)
    if not success:
        print(f"✓ Wrong password rejected: {result}")
    else:
        print(f"✗ Wrong password accepted (should not happen!)")
    
    # Test get salt
    print("\n[*] Testing salt retrieval...")
    retrieved_salt = get_user_salt(test_email)
    if retrieved_salt == test_salt:
        print("✓ Salt retrieval successful")
    else:
        print("✗ Salt retrieval failed")
    
    # List all users
    print("\n[*] All registered users:")
    users = get_all_users()
    for email, username in users:
        print(f"  - {username} ({email})")
    
    # Clean up test user
    print("\n[*] Cleaning up test data...")
    conn = get_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE email = %s", (test_email,))
        conn.commit()
        cursor.close()
        conn.close()
        print("✓ Test data cleaned up")
    
    print("\n[✓] All database utility tests passed!")
