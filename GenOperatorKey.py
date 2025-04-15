from nacl.public import PrivateKey, PublicKey
import binascii

def generate_keypair():
    # Generate a new private key (this also generates the corresponding public key)
    private_key = PrivateKey.generate()
    public_key = private_key.public_key

    # Convert keys to bytes
    private_key_bytes = private_key.encode()
    public_key_bytes = public_key.encode()

    # Convert to hex for easy use in C++
    private_key_hex = binascii.hexlify(private_key_bytes).decode('ascii')
    public_key_hex = binascii.hexlify(public_key_bytes).decode('ascii')

    # Format as C++ array for direct copy-paste
    private_key_cpp = ', '.join(f'0x{private_key_hex[i:i+2]}' for i in range(0, len(private_key_hex), 2))
    public_key_cpp = ', '.join(f'0x{public_key_hex[i:i+2]}' for i in range(0, len(public_key_hex), 2))

    return private_key_hex, public_key_hex, private_key_cpp, public_key_cpp

def main():
    # Generate the keys
    private_key_hex, public_key_hex, private_key_cpp, public_key_cpp = generate_keypair()

    # Print results
    print("Private Key (hex, 64 characters, keep secret):")
    print(private_key_hex)
    print("\nPublic Key (hex, 64 characters, embed in encryption program):")
    print(public_key_hex)
    print("\nPrivate Key (C++ array format):")
    print(f"static const unsigned char OPERATOR_PRIVATE_KEY[crypto_box_SECRETKEYBYTES] = {{{private_key_cpp}}};")
    print("\nPublic Key (C++ array format):")
    print(f"static const unsigned char OPERATOR_PUBLIC_KEY[crypto_box_PUBLICKEYBYTES] = {{{public_key_cpp}}};")

    # Save to files for convenience
    with open("private_key.txt", "w") as f:
        f.write(private_key_hex)
    with open("public_key.txt", "w") as f:
        f.write(public_key_hex)
    print("\nKeys also saved to 'private_key.txt' and 'public_key.txt'.")

if __name__ == "__main__":
    main()