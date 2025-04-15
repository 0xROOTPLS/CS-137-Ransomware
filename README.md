# CS-137-Ransomware Prototype PoC

This repository contains a complete Cs-137 ransomware toolkit, including the ransomware, and operator tool suite.

## Files

- **cs137.cpp**: Main ransomware payload that encrypts victim files
- **GenOperatorKey.py**: Attacker utility for generating asymmetric key pairs
- **OperatorDecrypt.py**: Attacker utility for recovering encryption keys from victim IDs
- **decrypt_cs137.cpp**: Decryption tool provided to victims after ransom payment

## Detailed Analysis

### cs137.cpp (Ransomware Payload - Encryptor)

**Purpose**: Encrypts files on the victim's machine and demands ransom.

**Functionality**:
  
- **Victim-Specific Key Generation**:
  - Generates random 32-byte ChaCha20 key and 8-byte nonce with `randombytes_buf`
  - Each victim instance receives unique key/nonce pair
  
- **Unique ID Generation**:
  - Concatenates the generated key and nonce (40 bytes total)
  - Encrypts the combined data using `crypto_box_seal` with hardcoded operator's public key
  - Converts the ciphertext to hexadecimal string
  - This ID securely contains the victim's decryption key/nonce, only readable with attacker's private key
  
- **File Encryption**:
  - Targets user directories (Desktop, Documents, Pictures, etc.)
  - Encrypts files with `crypto_stream_chacha20_xor` using victim-specific key/nonce
  - Overwrites original files with format: `MAGIC_STRING + encrypted_data + nonce`

**Role**: Core malicious component that encrypts files and notifies the victim.

### GenOperatorKey.py (Attacker Utility - Key Generation)

**Purpose**: Generates the master asymmetric key pair for the attacker (the "operator").

**Functionality**:
- Uses the pynacl library (Python binding for Libsodium)
- Creates a secure Curve25519 key pair
- Formats keys as C++ unsigned char arrays for easy embedding in source code
- Saves keys to `private_key.txt` (SECRET) and `public_key.txt` (for embedding)

**Role**: One-time setup script run by the attacker before compiling the ransomware.

### OperatorDecrypt.py (Attacker Utility - Key Recovery)

**Purpose**: Used by attacker to derive the victim's ChaCha20 key/nonce from the provided unique ID.

**Functionality**:
- Contains hardcoded attacker's private and public keys (from GenOperatorKey.py)
- Takes victim's unique ID (hex string) as input
- Extracts original 32-byte ChaCha20 key and 8-byte nonce from decrypted data
- Saves result to `decryption_key.txt`

**Role**: Attacker's tool to process victim's unique identifier and generate decryption key material.

### decrypt_cs137.cpp (Victim Utility - Decryptor)

**Purpose**: Tool provided to victim (after ransom payment) to decrypt files.

**Functionality**:
- **Key Input**: Prompts user for 80-character hex decryption key from attacker
- **Key Parsing**: Validates length, converts to bytes, splits into key and nonce components
- **File Decryption**:
  - Identifies same target directories as the encryptor
  - Checks for `MAGIC_STRING` with `is_file_encrypted` and reads embedded nonce
  - Compares file nonce with provided nonce as a sanity check
  - Decrypts data with `crypto_stream_chacha20_xor` using provided key and nonce
  - Overwrites file with only the decrypted content, removing markers

**Role**: Tool that reverses the encryption done by cs137.cpp when provided with the correct key.

## Operator Workflow

1. **Preparation**:
   - Run GenOperatorKey.py to generate asymmetric key pair
   - Embed public key in cs137.cpp
   - Compile cs137.cpp (encryptor) and decrypt_cs137.cpp (decryptor)
   - Keep private key secure

2. **Infection**:
   - cs137.cpp executes on victim machine

3. **Encryption**:
   - Generates unique ChaCha20 key/nonce
   - Encrypts target files
   - Encrypts key/nonce with operator public key to create unique_id
   - Displays ransom note with unique_id and changes wallpaper

4. **Ransom/Communication**:
   - Victim sees ransom note
   - Contacts attacker and provides unique_id
   - Pays ransom

5. **Key Recovery**:
   - Attacker uses OperatorDecrypt.py with private key to decrypt unique_id
   - Recovers victim's ChaCha20 key/nonce
   - Generates 80-character decryption_key_hex

6. **Decryption**:
   - Attacker provides decryption_key_hex and decrypt_cs137.cpp to victim
   - Victim runs decryptor and enters decryption_key_hex
   - Files are decrypted using recovered key/nonce

## Technical Details

- **Encryption Algorithm**: ChaCha20 stream cipher
- **Key Exchange**: Curve25519 (via Libsodium/NaCl)
- **Victim Identifier**: Encrypted blob containing victim-specific ChaCha20 key/nonce
- **File Format**: MAGIC_STRING + encrypted_data + nonce
- **Dependencies**: Libsodium (C++), pynacl (Python)

## Security Research Notice

This repository is for educational and research purposes only. The code and functionality of PoC malware to improve detection and prevention measures. Do not use this code for malicious purposes.
