<?php

namespace EbicsApi\Ebics\Contracts;

use EbicsApi\Ebics\Models\Crypt\Key;
use EbicsApi\Ebics\Models\Crypt\KeyPair;
use EbicsApi\Ebics\Models\Keyring;
use LogicException;
use RuntimeException;

/**
 * Crypt Service interface.
 *
 * Provides all cryptographic operations required by the EBICS protocol:
 *  - Hashing (SHA-256)
 *  - AES-128-CBC encrypt/decrypt
 *  - RSA encrypt/decrypt and signature encoding (A005/A006)
 *  - Key pair generation and management
 *  - X.509 certificate fingerprinting
 *  - Random value generation (nonces, transaction keys, order IDs)
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
interface CryptServiceInterface
{
    /**
     * Compute a cryptographic hash of the given text.
     *
     * @param string $text      The input data to hash.
     * @param string $algorithm Hash algorithm name (default 'sha256').
     * @param bool   $binary    If true, return raw binary; otherwise lowercase hex.
     *
     * @return string Hash output.
     */
    public function hash(string $text, string $algorithm = 'sha256', bool $binary = true): string;

    /**
     * Decrypt compressed order data received from the bank.
     *
     * RSA-decrypts the transaction key using the user's Signature E private key,
     * then AES-decrypts the order data with the recovered key.
     *
     * @param Keyring $keyring          Keyring containing Signature E private key
     * @param string  $orderDataEncrypted AES-encrypted order data
     * @param string  $transactionKey   RSA-encrypted transaction key (base64-decoded)
     *
     * @return string Decrypted (still compressed) order data
     *
     * @throws RuntimeException If Signature E or private key is missing, or decryption fails
     */
    public function decryptOrderDataCompressed(
        Keyring $keyring,
        string $orderDataEncrypted,
        string $transactionKey
    ): string;

    /**
     * Decrypt data using a raw AES key (AES-128-CBC).
     *
     * @param string $key  The raw AES decryption key
     * @param string $data The AES-encrypted ciphertext
     *
     * @return string Decrypted plaintext
     */
    public function decryptByKey(string $key, string $data): string;

    /**
     * Encrypt data using a raw AES key (AES-128-CBC).
     *
     * @param string $key  The raw AES encryption key
     * @param string $data The plaintext to encrypt
     *
     * @return string AES-encrypted ciphertext
     */
    public function encryptByKey(string $key, string $data): string;

    /**
     * RSA-public-key encrypt a transaction key.
     *
     * @param Key    $publicKey     RSA public key (Signature E)
     * @param string $transactionKey The raw AES transaction key to encrypt
     *
     * @return string RSA-encrypted transaction key
     */
    public function encryptTransactionKey(Key $publicKey, string $transactionKey): string;

    /**
     * Encode data for RSA signature (does not perform the RSA operation).
     *
     * Produces the encoded message representative that would be signed.
     * The actual RSA private-key signing is performed by the caller afterward.
     *
     *  - **A005**: EMSA-PKCS1-v1_5 encoding with SHA-256.
     *  - **A006**: EMSA-PSS encoding with SHA-256 and MGF1-SHA-256.
     *    Includes a self-verification step; throws if encoding is incorrect.
     *
     * @param Key    $privateKey RSA private key (used for key parameters only)
     * @param string $password   Password to decrypt the private key
     * @param string $version    EBICS version constant (SignatureInterface::A_VERSION5 or A_VERSION6)
     * @param string $data       Raw data to encode for signing
     *
     * @return string The encoded message representative
     *
     * @throws LogicException If the version is unsupported or PSS self-verification fails
     */
    public function sign(
        Key $privateKey,
        string $password,
        string $version,
        string $data
    ): string;

    /**
     * Encrypt/sign data using RSA private key for EBICS authentication.
     *
     * The behaviour depends on the EBICS authentication version:
     *
     *  - **A006** (RSA-PSS): Signs the raw data using EMSA-PSS with SHA-256.
     *  - **A005** (RSA-PKCS#1 v1.5): Hashes the data with SHA-256, prepends
     *    the DigestInfo ASN.1 prefix, then RSA-encrypts the result.
     *
     * @param Key    $privateKey RSA private key (Signature A)
     * @param string $password   Password to decrypt the private key
     * @param string $version    EBICS version constant (SignatureInterface::A_VERSION5 or A_VERSION6)
     * @param string $data       Raw data to encrypt/sign
     *
     * @return string RSA-encrypted/signed output
     *
     * @throws RuntimeException If encryption fails
     */
    public function encrypt(
        Key $privateKey,
        string $password,
        string $version,
        string $data
    ): string;

    /**
     * Verify an RSA signature over the message.
     *
     * The behaviour depends on the EBICS authentication version:
     *
     *  - **A005 / X002** (RSA-PKCS#1 v1.5): Verifies RSASSA-PKCS1-v1_5 with SHA-256.
     *    Mirrors the encrypt() A005 path: the signature must be a PKCS#1 v1.5
     *    signature of the SHA-256 DigestInfo structure computed over the message.
     *  - **A006** (RSA-PSS): Verifies RSASSA-PSS with SHA-256 and MGF1-SHA-256.
     *    Mirrors the encrypt() A006 path.
     *
     * Used to verify the bank authentication signature of EBICS responses.
     * The bank signature version is typically X002 (PKCS#1 v1.5), but A005/A006
     * are also accepted for environments where the bank uses the same scheme
     * as the client authentication signature.
     *
     * @param Key    $publicKey RSA public key (bank Signature X002 or A)
     * @param string $message   The original message that was signed (e.g., canonicalized ds:SignedInfo)
     * @param string $signature Raw binary signature (base64-decoded ds:SignatureValue)
     * @param string $version   EBICS version constant (SignatureInterface::A_VERSION5, A_VERSION6 or X_VERSION2)
     *
     * @return bool True if the signature is valid, false otherwise
     */
    public function verify(
        Key $publicKey,
        string $message,
        string $signature,
        string $version
    ): bool;

    /**
     * Generate an RSA key pair for EBICS signatures.
     *
     * @param string $password  Password to encrypt the private key
     * @param string $algorithm Hash algorithm for the key (default 'sha256')
     * @param int    $length    RSA key length in bits (default 2048)
     *
     * @return KeyPair Generated key pair with PEM-encoded keys
     */
    public function generateKeyPair(
        string $password,
        string $algorithm = 'sha256',
        int $length = 2048
    ): KeyPair;

    /**
     * Unpack a binary string into an array of unsigned byte values.
     *
     * @param string $bytes Binary string to convert
     *
     * @return array<int, int> Array of byte values (0-255), 1-indexed
     */
    public function binToArray(string $bytes): array;

    /**
     * Calculate the hash digest of an RSA public key from a signature.
     *
     * @param SignatureInterface $signature The signature containing the public key
     * @param string             $algorithm Hash algorithm (default 'sha256')
     *
     * @return string Raw binary hash of the public key
     */
    public function calculatePublicKeyDigest(SignatureInterface $signature, string $algorithm = 'sha256'): string;

    /**
     * Format a public key string from hex-encoded exponent and modulus.
     *
     * @param string $exponent Hex-encoded RSA exponent
     * @param string $modulus  Hex-encoded RSA modulus
     *
     * @return string Formatted string "<exponent> <modulus>"
     */
    public function calculateKey(string $exponent, string $modulus): string;

    /**
     * Calculate the X.509 certificate fingerprint.
     *
     * Accepts either PEM-encoded or raw DER certificate content.
     *
     * @param string $certContent PEM or DER certificate content
     * @param string $algorithm   Hash algorithm (default 'sha256')
     * @param bool   $rawOutput   If true, return raw binary; otherwise lowercase hex
     *
     * @return string Certificate fingerprint
     */
    public function calculateCertificateFingerprint(
        string $certContent,
        string $algorithm = 'sha256',
        bool $rawOutput = true
    ): string;

    /**
     * Generate a random 32-character uppercase hex string (16 bytes of entropy).
     *
     * @return string Hex nonce
     */
    public function generateNonce(): string;

    /**
     * Generate a 16-byte random AES transaction key.
     *
     * @return string Raw 16-byte binary key
     */
    public function generateTransactionKey(): string;

    /**
     * Extract the RSA exponent and modulus from a public key as raw byte strings.
     *
     * @param Key $publicKey RSA public key in PEM format
     *
     * @return array{e: string, m: string} Exponent and modulus as raw byte strings
     */
    public function decomposePublicKey(Key $publicKey): array;

    /**
     * Generate a random 4-character EBICS order ID.
     *
     * Format: one uppercase letter (A-Z) followed by three alphanumeric characters.
     *
     * @return string 4-character order ID
     */
    public function generateOrderId(): string;

    /**
     * Verify that an RSA private key can be decrypted with the given password.
     *
     * @param Key    $privateKey RSA private key in PEM format
     * @param string $password   Password to attempt decryption with
     *
     * @return bool True if the key loads successfully, false otherwise
     */
    public function checkPrivateKey(Key $privateKey, string $password): bool;

    /**
     * Re-encrypt an RSA key pair with a new password.
     *
     * @param KeyPair $keyPair    The key pair to re-encrypt
     * @param string  $oldPassword Current password
     * @param string  $newPassword New password to apply
     *
     * @return KeyPair New key pair encrypted with the new password
     */
    public function changePrivateKeyPassword(KeyPair $keyPair, string $oldPassword, string $newPassword): KeyPair;
}
