<?php
class Crypto {

    // Constants for key, salt, and nonce sizes, and key derivation parameters
    private static $KEY_SIZE = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
    private static $SALT_SIZE = SODIUM_CRYPTO_PWHASH_SALTBYTES;
    private static $NONCE_SIZE = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    private static $OPS_LIMIT = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
    private static $MEM_LIMIT = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;

    /**
     * Encrypts a plaintext message using a password-derived key and XChaCha20-Poly1305 AEAD.
     */
    public static function encrypt(string $str, string $pwd, string $additionalData = ''): string|false {
        if (empty($str) || empty($pwd)) {
            return false; // Return false if input is empty
        }

        try {
            // Generate random salt and nonce
            $salt = random_bytes(self::$SALT_SIZE);
            $nonce = random_bytes(self::$NONCE_SIZE);

            // Derive key from password
            $key = sodium_crypto_pwhash(
                self::$KEY_SIZE,
                $pwd,
                $salt,
                self::$OPS_LIMIT,
                self::$MEM_LIMIT
            );

            // Encrypt the message
            $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $str,
                $additionalData,
                $nonce,
                $key
            );

            // Clear key from memory
            sodium_memzero($key);

            // Return hex-encoded result
            return bin2hex($salt . $nonce . $ciphertext);

        } catch (SodiumException | Exception $e) {

            //error_log("Crypto encryption error: " . $e->getMessage() . " [Operation: encrypt]");
            return false;
        }
    }

    /**
     * Decrypts a hex-encoded ciphertext message.
     */
    public static function decrypt(string $str, string $pwd, string $additionalData = ''): string|false {

        if (empty($str) || empty($pwd)) {
            return false;
        }

        try {

            // Decode hex to binary
            $decoded = hex2bin($str);

            // Validate minimum length
            if ($decoded === false || strlen($decoded) < self::$SALT_SIZE + self::$NONCE_SIZE + 1) {
                return false;
            }

            // Extract salt, nonce, and ciphertext
            $salt = substr($decoded, 0, self::$SALT_SIZE);
            $nonce = substr($decoded, self::$SALT_SIZE, self::$NONCE_SIZE);
            $ciphertext = substr($decoded, self::$SALT_SIZE + self::$NONCE_SIZE);

            // Return false if extraction fails
            if (empty($salt) || empty($nonce) || empty($ciphertext)) {
                return false;
            }

            // Derive key from password
            $key = sodium_crypto_pwhash(
                self::$KEY_SIZE,
                $pwd,
                $salt,
                self::$OPS_LIMIT,
                self::$MEM_LIMIT
            );

            // Decrypt the message
            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ciphertext,
                $additionalData,
                $nonce,
                $key
            );

            // Clear key from memory
            sodium_memzero($key);

            // Return plaintext or false on failure
            return $plaintext !== false ? $plaintext : false;

        } catch (SodiumException | Exception $e) {
            return false;
        }
    }
}