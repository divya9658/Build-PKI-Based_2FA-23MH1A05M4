import pyotp
import base64
import os
import time
import hashlib # <--- ADDED: Needed for specifying the hashing algorithm
from typing import Optional

# Configuration Constants
TOTP_PERIOD = 30 # seconds (Requirement: 30 seconds)
TOTP_DIGITS = 6  # (Requirement: 6 digits)
# (Requirement: SHA-1, which is the default hash algorithm for pyotp)
TOTP_ALGORITHM = hashlib.sha1 # <--- CORRECTED: Use hashlib.sha1 instead of pyotp.hash_algorithms.SHA1
SEED_FILE_PATH = "data/seed.txt" # Path confirmed from Step 5

def hex_to_base32(hex_seed: str) -> Optional[str]:
    """
    Converts the 64-character hex seed into a Base32 encoded string suitable for pyotp.
    
    Args:
        hex_seed: 64-character hex string.
        
    Returns:
        Optional[str]: Base32 encoded key (uppercase) or None on conversion failure.
    """
    # 1. Convert 64-char hex string (32 bytes) to raw bytes
    try:
        raw_seed_bytes = bytes.fromhex(hex_seed)
    except ValueError:
        print("Error: Input hex_seed is not a valid 64-character hexadecimal string.")
        return None

    # 2. Encode the raw bytes into Base32. pyotp requires the key to be Base32.
    # .b32encode returns bytes, we decode to string and strip padding '='
    base32_seed_key = base64.b32encode(raw_seed_bytes).decode('utf-8').strip("=")
    
    # The key must be in uppercase for pyotp
    return base32_seed_key.upper()

def get_totp_object(hex_seed: str) -> Optional[pyotp.TOTP]:
    """Helper function to convert seed and initialize the TOTP object."""
    base32_key = hex_to_base32(hex_seed)
    if not base32_key:
        return None
        
    # 3. Create TOTP object using pyotp
    return pyotp.TOTP(
        base32_key, 
        digits=TOTP_DIGITS, 
        interval=TOTP_PERIOD, 
        digest=TOTP_ALGORITHM
    )

def generate_totp_code(hex_seed: str) -> Optional[str]:
    """
    Generate current TOTP code from hex seed
    
    Args:
        hex_seed: 64-character hex string
    
    Returns:
        6-digit TOTP code as string
    
    Implementation:
    1. Convert hex seed to bytes
    2. Convert bytes to base32 encoding
    3. Create TOTP object using pyotp
    4. Generate current TOTP code
    5. Return the code
    """
    totp = get_totp_object(hex_seed)
    if not totp:
        return None

    # 4. Generate current TOTP code
    return totp.now()

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with time window tolerance
    
    Args:
        hex_seed: 64-character hex string
        code: 6-digit code to verify
        valid_window: Number of periods before/after to accept (default 1 = ±30s)
        
    Returns:
        True if code is valid, False otherwise
    
    Implementation:
    1. Convert hex seed to base32 
    2. Create TOTP object with base32 seed
    3. Verify code with time window tolerance
    4. Return verification result
    """
    totp = get_totp_object(hex_seed)
    if not totp:
        return False

    # 3. Verify code with time window tolerance (default window=1 checks current, previous, and next 30s window)
    return totp.verify(code, valid_window=valid_window)

def run_totp_process():
    """Main execution function for Step 6, loads seed and demonstrates usage."""
    # Load the hex seed from the file
    if not os.path.exists(SEED_FILE_PATH):
        print(f"FATAL ERROR: Seed file '{SEED_FILE_PATH}' not found.")
        print("Please ensure Step 5 was run and created the data/seed.txt file.")
        return

    try:
        with open(SEED_FILE_PATH, "r") as f:
            hex_seed = f.read().strip()
    except Exception as e:
        print(f"Error reading seed file: {e}")
        return

    # Check for valid seed length 
    if len(hex_seed) != 64:
        print(f"FATAL ERROR: Seed in file is incorrect length ({len(hex_seed)} chars), expected 64.")
        return

    # 1. Generate the current token
    current_totp = generate_totp_code(hex_seed)

    if current_totp:
        # Calculate the remaining time in the current window for user convenience
        current_time_s = time.time()
        time_remaining = TOTP_PERIOD - (int(current_time_s) % TOTP_PERIOD)
        
        print("\n--- Step 6: TOTP Generation Complete ---")
        print(f"Using Seed from: {SEED_FILE_PATH}")
        print(f"Configuration: SHA1, {TOTP_PERIOD}s period, {TOTP_DIGITS} digits")
        print(f"CURRENT TOTP: {current_totp}")
        print(f"Token will expire in {time_remaining} seconds.")
        
        # 2. Demonstration of Verification
        print("\n--- Verification Demonstration (Self-Check) ---")
        
        # Check against the generated code (should be True)
        is_valid_now = verify_totp_code(hex_seed, current_totp)
        print(f"Verification of current code '{current_totp}' (window 1): {is_valid_now}")
        
        # Check against a dummy code (should be False)
        is_valid_dummy = verify_totp_code(hex_seed, "999999")
        print(f"Verification of dummy code '999999' (window 1): {is_valid_dummy}")
        print("------------------------------------------")


if __name__ == '__main__':
    run_totp_process()