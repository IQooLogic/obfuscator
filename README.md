# Welcome to IQooLogic/obfuscator - Go Package for Sensitive Data Obfuscation

Introduction
------------
The `obfuscator` package provides functionality for Go applications to securely encode and decode sensitive strings, such as passwords or API keys, making them safer to store in configuration files or transmit. It uses robust cryptographic methods to ensure data protection.

Internally, it employs:
* **AES-GCM:** For authenticated encryption, ensuring both confidentiality and integrity of the data.
* **PBKDF2:** With a configurable hash function (defaulting to SHA256) to derive a strong encryption key from a user-provided passphrase and a random salt.
* **Random Salt & IV:** Generates a unique salt and initialization vector (IV) for each obfuscation operation to enhance security.

The obfuscated output includes the version, salt, IV, and ciphertext, typically separated by a configurable separator (default is `$`), allowing for reliable unobfuscation later.


#### Important Note on Output

The Obfuscate function is non-deterministic. This means calling it multiple times with the exact same input text and passphrase will produce different output strings each time. This is intentional and enhances security, as it relies on generating a unique random salt and a unique random Initialization Vector (IV) for every encryption operation.


Data protected
------------

The package combines several standard, well-regarded cryptographic techniques to protect the data:

1. **AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)**:

    - **What it is:** AES is a symmetric block cipher chosen by the U.S. government to protect classified information. It's widely adopted globally. The code uses AES to perform the actual encryption and decryption of the input text. GCM is a mode of operation for symmetric key ciphers (like AES) that provides _authenticated encryption_.
    - **Why it's robust:**
        - **Confidentiality:** AES itself (with a sufficient key size, here derived to be 256-bit via PBKDF2) provides strong encryption, making the ciphertext very difficult to decrypt without the correct key.
        - **Authenticity & Integrity:** The GCM part is crucial. It computes an authentication tag (like a signature) over the ciphertext _and_ associated data (like the IV). When decrypting, GCM verifies this tag. If the ciphertext or the IV has been tampered with in any way, the tag verification will fail, and decryption will error out. This prevents attackers from modifying the encrypted data without detection.
    - **Usage in the package:** The `encrypt` and `decrypt` functions explicitly use `aes.NewCipher` and `cipher.NewGCM` to perform AES-GCM encryption and decryption.
2. **PBKDF2 (Password-Based Key Derivation Function 2)**:

    - **What it is:** PBKDF2 is a standard algorithm (defined in RFC 2898/PKCS #5 v2.0) designed to produce a strong cryptographic key from a password or passphrase, which might otherwise be relatively weak. It does this by repeatedly hashing the passphrase along with a unique salt.
    - **Why it's robust:**
        - **Slows Down Brute-Force Attacks:** It's intentionally computationally intensive. By applying a pseudorandom function (like HMAC-SHA256) many times (the iteration count), it significantly increases the time and resources required for an attacker to guess the original passphrase by trying possibilities against a captured obfuscated string. The code uses a fixed iteration count of 1000.
        - **Salting:** Using a unique, random salt for each obfuscation (as done by `generateSalt`) means that even if two users use the same passphrase, the derived keys and the resulting obfuscated strings will be different. This prevents attackers from using precomputed tables (like rainbow tables) to crack multiple passphrases at once.
    - **Usage in the package:** The `deriveKey` function uses `pbkdf2.Key` from the `golang.org/x/crypto/pbkdf2` package, specifically with `sha256.New` as the hash function, a random salt generated per operation, and 1000 iterations to derive a 32-byte (256-bit) key suitable for AES.
3. **Random Salt and IV (Initialization Vector)**:

    - **What they are:** A salt is random data mixed with the passphrase before key derivation. An IV is random data used to initialize the encryption process for modes like GCM.
    - **Why they're robust:** Using a unique, cryptographically random salt and IV for _every_ obfuscation operation is critical.
        - The unique salt ensures the PBKDF2 output is unique even for identical passphrases, as mentioned above.
        - The unique IV ensures that encrypting the same plaintext multiple times (even with the same key) produces different ciphertexts. This prevents attackers from identifying patterns or knowing if the same message was sent twice. GCM specifically requires a unique IV for each encryption with the same key for its security guarantees.
    - **Usage in the package:** The `generateSalt` function creates a random salt of configurable length, and `genCryptoKey` creates a random 12-byte IV before each encryption. Both are encoded and stored alongside the ciphertext in the final output string.

In summary, the package doesn't invent new cryptography but correctly applies standard, well-vetted algorithms (AES-GCM, PBKDF2 with SHA256) and best practices (unique salts and IVs) to provide strong protection against unauthorized access and tampering, assuming a strong passphrase is used.

Installation and usage
----------------------

The import path for the package is `*github.com/IQooLogic/obfuscator*`.

To install it, run:

    go get github.com/IQooLogic/obfuscator

License
-------

The obfuscator package is licensed under the MIT license.
Please see the LICENSE file for details.

See [`LICENSE`](./LICENSE)

Example
-------

```Go
package main

import (
	"fmt"
	"github.com/IQooLogic/obfuscator"
)

func main() {
	originalText := "simple text or password"
	o := obfuscator.New([]byte("randompassphrase"))
	// obfuscate
	obfuscatedText, err := o.Obfuscate(originalText)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	fmt.Printf("Obfuscated text: %s\n", obfuscatedText)

	// unobfuscate
	unobfuscatedText, err := o.Unobfuscate(obfuscatedText)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	fmt.Printf("Unobfuscated text: %s\n", unobfuscatedText)
}
```

See [`Examples`](./examples)