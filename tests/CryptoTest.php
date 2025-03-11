<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Crypto.php';

class CryptoTest extends TestCase {

    public function testEncryptDecrypt() {
        $plaintext = "Secret message";
        $password = "securePassword123";

        $encrypted = Crypto::encrypt($plaintext, $password);
        $this->assertNotFalse($encrypted, "Encryption failed");

        $decrypted = Crypto::decrypt($encrypted, $password);
        $this->assertNotFalse($decrypted, "Decryption failed");
        $this->assertEquals($plaintext, $decrypted, "Decrypted text does not match");
    }

    public function testEncryptWithAdditionalData() {
        $plaintext = "Another secret message";
        $password = "anotherSecurePassword";
        $aad = "additional_data";

        $encrypted = Crypto::encrypt($plaintext, $password, $aad);
        $this->assertNotFalse($encrypted, "Encryption with AAD failed");

        $decrypted = Crypto::decrypt($encrypted, $password, $aad);
        $this->assertNotFalse($decrypted, "Decryption with AAD failed");
        $this->assertEquals($plaintext, $decrypted, "Decrypted text with AAD does not match");
    }

    public function testDecryptWithWrongPassword() {
        $plaintext = "Test message";
        $password = "correctPassword";
        $wrongPassword = "wrongPassword";

        $encrypted = Crypto::encrypt($plaintext, $password);
        $this->assertNotFalse($encrypted, "Encryption failed");

        $decrypted = Crypto::decrypt($encrypted, $wrongPassword);
        $this->assertFalse($decrypted, "Decryption with wrong password should fail");
    }

    public function testDecryptWithWrongAAD() {
        $plaintext = "Message with AAD";
        $password = "securePassword";
        $aad = "valid_aad";
        $wrongAad = "invalid_aad";

        $encrypted = Crypto::encrypt($plaintext, $password, $aad);
        $this->assertNotFalse($encrypted, "Encryption with AAD failed");

        $decrypted = Crypto::decrypt($encrypted, $password, $wrongAad);
        $this->assertFalse($decrypted, "Decryption with wrong AAD should fail");
    }

    public function testEncryptEmptyString() {
        $this->assertFalse(Crypto::encrypt("", "password"), "Encryption of an empty string should fail");
    }

    public function testDecryptInvalidData() {
        $this->assertFalse(Crypto::decrypt("123456", "password"), "Decryption of invalid data should fail");
    }
}
