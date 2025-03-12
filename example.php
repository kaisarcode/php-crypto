<?php
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