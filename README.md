# Crypto Class
A PHP class for secure encryption and decryption using **XChaCha20-Poly1305** (AEAD) and **Argon2** for password-based key derivation. This class is designed to be simple, secure, and easy to use.

## Requirements
- PHP 7.2 or higher.
- The [Sodium extension](https://www.php.net/manual/en/book.sodium.php) must be enabled.

## Implementation
```php
require 'vendor/autoload.php';

use KaisarCode\Crypto\Crypto;

$plaintext = "This is a secret message.";
$password = "supersecurepassword123";
$additionalData = "contextual-data"; // Optional

// Encrypt
$encrypted = Crypto::encrypt($plaintext, $password, $additionalData);
if ($encrypted === false) {
    die("Encryption failed.");
}
echo "Encrypted (Hex): " . $encrypted . "\n";

// Decrypt
$decrypted = Crypto::decrypt($encrypted, $password, $additionalData);
if ($decrypted === false) {
    die("Decryption failed.");
}
echo "Decrypted: " . $decrypted . "\n";
```

### Output
```
Encrypted (Hex): 320614d8b88a98adf16a7f810fcdc5b093faa089d8c6cfdab7f751d16c489317e13cb5e9fca31833b25bf9fa9a8ef6f8368d7db995d768c71d8ccb22d795984b0b5091
Decrypted: This is a secret message.
```

## Features
- **Secure Encryption**: Uses the `XChaCha20-Poly1305` algorithm for authenticated encryption.
- **Password-Based Key Derivation**: Uses `Argon2` (via `sodium_crypto_pwhash`) to derive keys from passwords.
- **Automatic Salt and Nonce Generation**: The salt and nonce are generated internally and prepended to the ciphertext.
- **Hex Encoding**: Outputs and inputs are hex-encoded for easy storage and transmission.
- **Memory Safety**: Sensitive data (e.g., keys) is cleared from memory after use using `sodium_memzero`.

## Methods

### `encrypt(string $str, string $pwd, string $additionalData = ''): string|false`
- Encrypts a plaintext message using a password-derived key.
- **Parameters**:
  - `$str`: The plaintext message to encrypt.
  - `$pwd`: The password used for key derivation.
  - `$additionalData`: Optional additional authenticated data (AD).
- **Returns**: A hex-encoded string containing the encrypted ciphertext, or `false` on failure.

### `decrypt(string $str, string $pwd, string $additionalData = ''): string|false`
- Decrypts a hex-encoded ciphertext message using a password-derived key.
- **Parameters**:
  - `$str`: The hex-encoded encrypted message.
  - `$pwd`: The password used for key derivation.
  - `$additionalData`: Optional additional authenticated data (AD).
- **Returns**: The decrypted plaintext, or `false` on failure.

---

## Security Notes
- **Password Strength**: The security of the encryption depends on the strength of the password. Use strong, randomly generated passwords.
- **Additional Data**: The `additionalData` parameter is optional but can be used to bind the ciphertext to a specific context (e.g., a user ID or session token).
- **Memory Safety**: Sensitive data (e.g., keys) is cleared from memory after use to prevent leaks.

---

Licensed under [MIT License](https://opensource.org/license/mit)