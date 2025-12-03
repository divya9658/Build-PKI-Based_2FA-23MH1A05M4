import base64
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from typing import Optional

def load_private_key(filepath: str = "student_private.pem"):
    """
    Loads the RSA private key from the PEM file.
    
    Args:
        filepath (str): Path to the private key file.

    Returns:
        rsa.RSAPrivateKey: The loaded private key object.
    """
    if not os.path.exists(filepath):
        print(f"Error: Private key file not found at {filepath}")
        return None
        
    try:
        with open(filepath, "rb") as key_file:
            private_key = load_pem_private_key(
                key_file.read(),
                password=None,  # Key was generated without a password
            )
        return private_key
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None

def decrypt_seed(encrypted_seed_b64: str, private_key: rsa.RSAPrivateKey) -> Optional[str]:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP.
    
    Args:
        encrypted_seed_b64: Base64-encoded ciphertext string.
        private_key: RSA private key object.
        
    Returns:
        Optional[str]: Decrypted hex seed (64-character string) or None on failure.
    """
    try:
        # 1. Base64 decode the encrypted seed string
        ciphertext = base64.b64decode(encrypted_seed_b64)
        
        # 2. RSA/OAEP decrypt with SHA-256
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 3. Decode bytes to UTF-8 string (the seed is a hex string)
        hex_seed = plaintext.decode('utf-8')
        
        # 4. Validate: must be 64-character hex string
        if len(hex_seed) != 64:
            print(f"Validation Error: Decrypted seed length is {len(hex_seed)}, expected 64.")
            return None
            
        if not all(c in '0123456789abcdef' for c in hex_seed.lower()):
            print("Validation Error: Decrypted seed contains non-hexadecimal characters.")
            return None
            
        # 5. Return hex seed
        print("\nDecryption SUCCESS.")
        return hex_seed
        
    except Exception as e:
        print(f"Decryption failed. Ensure the correct private key was used or the seed file is valid: {e}")
        return None

def run_decryption_process():
    """Reads encrypted seed and private key, performs decryption, and saves the final seed."""
    ENCRYPTED_SEED_FILE = "encrypted_seed.txt"
    OUTPUT_SEED_FILE = "seed.txt" # The required file name for the container

    # Load the encrypted seed
    if not os.path.exists(ENCRYPTED_SEED_FILE):
        print(f"FATAL ERROR: Encrypted seed file '{ENCRYPTED_SEED_FILE}' not found.")
        print("Please ensure Step 4 completed successfully.")
        return

    with open(ENCRYPTED_SEED_FILE, "r") as f:
        encrypted_seed_b64 = f.read().strip()
    
    # Load the private key
    private_key = load_private_key()
    if private_key is None:
        return

    # Perform decryption
    decrypted_seed = decrypt_seed(encrypted_seed_b64, private_key)
    
    if decrypted_seed:
        # Save the final decrypted seed
        with open(OUTPUT_SEED_FILE, "w") as f:
            f.write(decrypted_seed)
        
        print("\n--- Step 5 Complete ---")
        print(f"Decrypted Seed: {decrypted_seed}")
        print(f"Final seed saved to: {OUTPUT_SEED_FILE}")
        print(f"The seed is ready to be used as input for the TOTP function in the next step.")
        print("⚠️ NOTE: You may want to add 'seed.txt' to your .gitignore if it's not already there.")


if __name__ == '__main__':
    run_decryption_process()