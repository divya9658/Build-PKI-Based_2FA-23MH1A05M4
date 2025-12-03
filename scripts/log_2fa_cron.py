#!/usr/bin/env python3
"""
Cron script to log the current TOTP code every minute.
This script is executed by the cron scheduler inside the Docker container.
"""
import os
import pyotp
import base64
from datetime import datetime, timezone

# --- Configuration ---
# Path to the persistent storage file created by the API's decrypt endpoint
SEED_PATH = "/app/data/seed.txt" 
# The log file path where the output will be redirected by cron
LOG_FILE_PATH = "/app/cron/last_code.txt" 

def log_current_totp():
    """Reads the hex seed, generates the TOTP code, and prints the result."""
    
    # 1. Read hex seed from persistent storage
    try:
        if not os.path.exists(SEED_PATH):
            print(f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} - ERROR: Seed file not found at {SEED_PATH}. Has /decrypt-seed been called?")
            return

        with open(SEED_PATH, 'r') as f:
            # Read, strip whitespace, and ensure it's a clean hex string
            hex_seed = f.read().strip()
            if not hex_seed:
                print(f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} - ERROR: Seed file is empty.")
                return

    except Exception as e:
        print(f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} - FATAL ERROR reading seed: {e}")
        return

    # 2. Generate current TOTP code
    try:
        # Convert hex seed (string) to bytes
        seed_bytes = bytes.fromhex(hex_seed)
        
        # Base32 encode the bytes (this is the format pyotp expects for the secret)
        # Note: We use the canonical encoding, padding is usually added by pyotp
        base32_secret = base64.b32encode(seed_bytes).decode().replace('=', '')
        
        # Initialize TOTP generator
        totp = pyotp.TOTP(base32_secret)
        
        # Generate the current code
        current_code = totp.now()
        
    except Exception as e:
        print(f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} - FATAL ERROR generating TOTP: {e}")
        return

    # 3. Get current UTC timestamp
    # 4. Output formatted line to stdout (cron redirects this to /cron/last_code.txt)
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    print(f"{timestamp} - 2FA Code: {current_code}")


if __name__ == "__main__":
    log_current_totp()