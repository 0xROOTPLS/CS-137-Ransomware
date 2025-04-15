from nacl.public import PrivateKey, PublicKey
import binascii

# Operator's private key (hardcoded, replace with your generated private key from generate_keys.py)
OPERATOR_PRIVATE_KEY_HEX = "670ada9bea9665fbdfd2eb68151fd75a030a8021f6484ffb7fa15b63271c1464"  # Replace with your actual private key hex
OPERATOR_PUBLIC_KEY_HEX = "7bf5b75aec2393ca609942fdecd44d26042a9f3d62a9a309a5a13baa7d1db425"  # Replace with your actual public key hex

def hex_to_bytes(hex_str):
    return binascii.unhexlify(hex_str)

def extract_decryption_key(unique_id_hex):
    # Convert hex inputs to bytes
    private_key_bytes = hex_to_bytes(OPERATOR_PRIVATE_KEY_HEX)
    public_key_bytes = hex_to_bytes(OPERATOR_PUBLIC_KEY_HEX)
    unique_id_bytes = hex_to_bytes(unique_id_hex)

    # Load keys into PyNaCl objects
    private_key = PrivateKey(private_key_bytes)
    public_key = PublicKey(public_key_bytes)

    # Decrypt the Unique ID (sealed box)
    plaintext = private_key.decrypt(unique_id_bytes, public_key=public_key)

    # Extract ChaCha20 key (32 bytes) and nonce (8 bytes)
    chacha_key = plaintext[:32]  # First 32 bytes
    nonce = plaintext[32:]       # Last 8 bytes

    # Convert to hex for user
    chacha_key_hex = binascii.hexlify(chacha_key).decode('ascii')
    nonce_hex = binascii.hexlify(nonce).decode('ascii')
    decryption_key_hex = chacha_key_hex + nonce_hex  # 64 + 16 = 80 hex chars

    return decryption_key_hex

def main():
    unique_id = input("Enter the Unique ID from the user: ").strip()
    try:
        decryption_key = extract_decryption_key(unique_id)
        print(f"\nDecryption Key (send this to the user):")
        print(decryption_key)
        with open("decryption_key.txt", "w") as f:
            f.write(decryption_key)
        print("Decryption key also saved to 'decryption_key.txt'.")
    except Exception as e:
        print(f"Error: {e}")
        print("Check the Unique ID or ensure your private/public keys match the encryptor.")

if __name__ == "__main__":
    main()