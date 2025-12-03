import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from typing import Tuple

# --- Implementation Signature ---
def generate_rsa_keypair(key_size: int = 4096) -> Tuple[rsa.RSAPrivateNumbers, rsa.RSAPublicNumbers]:
    """
    Generates an RSA key pair with the specified size and standard public exponent.

    Args:
        key_size (int): The required key size in bits (default is 4096).

    Returns:
        Tuple: A tuple containing the (private_key, public_key) objects.
    """
    print(f"Generating a {key_size}-bit RSA key pair (e=65537)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_key_to_pem(key, filepath: str, is_private: bool):
    """
    Serializes an RSA key object to PEM format and saves it to a file.

    Args:
        key: The key object (private or public).
        filepath (str): The path to save the PEM file.
        is_private (bool): True if the key is private, False if public.
    """
    try:
        if is_private:
            # For the private key, we use NoEncryption since the requirement states
            # it MUST be committed to Git, suggesting a non-encrypted public key system setup.
            # In a real-world scenario, this should be password protected!
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        with open(filepath, "wb") as f:
            f.write(pem)

        print(f"Successfully saved {'Private' if is_private else 'Public'} Key to: {filepath}")

    except Exception as e:
        print(f"An error occurred while saving the key to {filepath}: {e}")


if __name__ == '__main__':
    # 1. Define file paths as required by the prompt
    PRIVATE_KEY_FILE = "student_private.pem"
    PUBLIC_KEY_FILE = "student_public.pem"
    KEY_SIZE = 4096

    # 2. Generate the key pair
    private_key, public_key = generate_rsa_keypair(key_size=KEY_SIZE)

    # 3. Save the keys to the required PEM files
    save_key_to_pem(private_key, PRIVATE_KEY_FILE, is_private=True)
    save_key_to_pem(public_key, PUBLIC_KEY_FILE, is_private=False)

    print("\n--- Verification ---")
    print(f"Files created: {PRIVATE_KEY_FILE} and {PUBLIC_KEY_FILE}")
    print("Remember to add, commit, and push these files to your GitHub repository.")
    print("e.g., git add student_private.pem student_public.pem")
    print("e.g., git commit -m \"Generated student key pair\"")
    print("e.g., git push")