<?php

namespace EbicsApi\Ebics\Services;

use EbicsApi\Ebics\Contracts\Crypt\RSAInterface;
use EbicsApi\Ebics\Contracts\CryptServiceInterface;
use EbicsApi\Ebics\Contracts\Processor\AESEncryptorInterface;
use EbicsApi\Ebics\Contracts\Processor\Base64EncoderInterface;
use EbicsApi\Ebics\Contracts\SignatureInterface;
use EbicsApi\Ebics\Factories\Crypt\RSAFactory;
use EbicsApi\Ebics\Models\Crypt\Key;
use EbicsApi\Ebics\Models\Crypt\KeyPair;
use EbicsApi\Ebics\Models\Crypt\RSA;
use EbicsApi\Ebics\Models\Keyring;
use LogicException;
use RuntimeException;

/**
 * CryptService provides cryptographic operations for EBICS protocol implementation.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 *
 * @internal This class is for internal use and may change without notice.
 */
final class CryptService implements CryptServiceInterface
{
    public function __construct(
        private readonly RSAFactory $rsaFactory,
        private readonly AESEncryptorInterface $aesEncryptor,
        private readonly RandomService $randomService,
        private readonly Base64EncoderInterface $base64Service
    ) {
    }

    /**
     * Compute a cryptographic hash of the given text.
     *
     * @param string $text      The input data to hash.
     * @param string $algorithm Hash algorithm name (default 'sha256').
     * @param bool   $binary    If true, return raw binary; otherwise lowercase hex.
     *
     * @return string Hash output.
     */
    public function hash(string $text, string $algorithm = 'sha256', bool $binary = true): string
    {
        return hash($algorithm, $text, $binary);
    }

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
    ): string {
        if (!($signatureE = $keyring->getUserSignatureE())) {
            throw new RuntimeException('Signature E is not set.');
        }
        $privateKey = $signatureE->getPrivateKey();
        if ($privateKey === null) {
            throw new RuntimeException('Signature E private key is not set.');
        }
        $rsa = $this->rsaFactory->createPrivate($privateKey, $keyring->getPassword());
        $transactionKeyDecrypted = $rsa->decrypt($transactionKey);

        return $this->decryptByKey($transactionKeyDecrypted, $orderDataEncrypted);
    }

    /**
     * Decrypt data using a raw AES key (AES-128-CBC).
     *
     * @param string $key  The raw AES decryption key
     * @param string $data The AES-encrypted ciphertext
     *
     * @return string Decrypted plaintext
     */
    public function decryptByKey(string $key, string $data): string
    {
        return $this->aesEncryptor->decrypt($data, [
            'key' => $key,
        ]);
    }

    /**
     * Encrypt data using a raw AES key (AES-128-CBC).
     *
     * @param string $key  The raw AES encryption key
     * @param string $data The plaintext to encrypt
     *
     * @return string AES-encrypted ciphertext
     */
    public function encryptByKey(string $key, string $data): string
    {
        return $this->aesEncryptor->encrypt($data, [
            'transactionKey' => $key,
        ]);
    }

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
    ): string {
        switch ($version) {
            case SignatureInterface::A_VERSION6:
                $rsa = $this->rsaFactory->createPrivate($privateKey, $password);
                $rsa->setHash('sha256');
                $rsa->setMGFHash('sha256');

                $encrypt = $rsa->sign($data);
                break;

            case SignatureInterface::A_VERSION5:
            default:
                $digestToSignBin = $this->filter($data);

                $rsa = $this->rsaFactory->createPrivate($privateKey, $password);

                $encrypt = $this->encryptByRsa($rsa, $digestToSignBin);
        }

        return $encrypt;
    }

    /**
     * @inheritDoc
     */
    public function verify(
        Key $publicKey,
        string $message,
        string $signature,
        string $version
    ): bool {
        $rsa = $this->rsaFactory->createPublic($publicKey);

        switch ($version) {
            case SignatureInterface::A_VERSION6:
                $rsa->setSignatureMode(RSA::SIGNATURE_PSS);
                $rsa->setHash('sha256');
                $rsa->setMGFHash('sha256');
                break;
            case SignatureInterface::A_VERSION5:
            case SignatureInterface::X_VERSION2:
            default:
                $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);
                $rsa->setHash('sha256');
                break;
        }

        return $rsa->verify($message, $signature);
    }

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
    ): string {
        switch ($version) {
            case SignatureInterface::A_VERSION5:
                $rsa = $this->rsaFactory->createPrivate($privateKey, $password);
                $rsa->setHash('sha256');
                $sign = $rsa->emsaPkcs1V15Encode($data);
                break;
            case SignatureInterface::A_VERSION6:
                $rsa = $this->rsaFactory->createPrivate($privateKey, $password);
                $rsa->setHash('sha256');
                $rsa->setMGFHash('sha256');
                $sign = $rsa->emsaPssEncode($data);
                if (!$rsa->emsaPssVerify($data, $sign)) {
                    throw new LogicException('Sign verification failed');
                }
                break;
            default:
                throw new LogicException(sprintf('Algorithm type for Version %s not supported', $version));
        }

        return $sign;
    }

    /**
     * RSA-public-key encrypt a transaction key.
     *
     * @param Key    $publicKey     RSA public key (Signature E)
     * @param string $transactionKey The raw AES transaction key to encrypt
     *
     * @return string RSA-encrypted transaction key
     *
     * @throws RuntimeException If encryption fails
     */
    public function encryptTransactionKey(Key $publicKey, string $transactionKey): string
    {
        return $this->encryptByRsaPublicKey($publicKey, $transactionKey);
    }

    /**
     * RSA-private-key encrypt data (PKCS#1 v1.5).
     *
     * @throws RuntimeException If encryption fails
     */
    private function encryptByRsa(RSAInterface $rsa, string $data): string
    {
        if (!($encrypted = $rsa->encrypt($data))) {
            throw new RuntimeException('Incorrect encryption.');
        }

        return $encrypted;
    }

    /**
     * RSA-public-key encrypt data (PKCS#1 v1.5).
     *
     * @throws RuntimeException If encryption fails
     */
    private function encryptByRsaPublicKey(Key $publicKey, string $data): string
    {
        $rsa = $this->rsaFactory->createPublic($publicKey);

        if (!($encrypted = $rsa->encrypt($data))) {
            throw new RuntimeException('Incorrect encryption.');
        }

        return $encrypted;
    }

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
    ): KeyPair {
        $rsa = $this->rsaFactory->create(RSA::PRIVATE_FORMAT_PKCS1);
        $rsa->setHash($algorithm);
        $rsa->setPassword($password);

        return $rsa->createKey($length);
    }

    /**
     * Prepend the SHA-256 DigestInfo ASN.1 prefix to a raw binary hash.
     *
     * Used by the A005 (RSA-PKCS#1 v1.5) encrypt path to construct the
     * DER-encoded DigestInfo structure required by EMSA-PKCS1-v1_5.
     *
     * @param string $hash Raw SHA-256 hash (32 bytes)
     *
     * @return string 51-byte DER-encoded DigestInfo structure (19-byte prefix + 32-byte hash)
     */
    private function filter(string $hash): string
    {
        $RSA_SHA256prefix = [
            0x30,
            0x31,
            0x30,
            0x0D,
            0x06,
            0x09,
            0x60,
            0x86,
            0x48,
            0x01,
            0x65,
            0x03,
            0x04,
            0x02,
            0x01,
            0x05,
            0x00,
            0x04,
            0x20,
        ];
        $unpHash = $this->binToArray($hash);
        $signedInfoDigest = array_values($unpHash);
        $digestToSign = [];
        $this->systemArrayCopy($RSA_SHA256prefix, 0, $digestToSign, 0, count($RSA_SHA256prefix));
        $this->systemArrayCopy($signedInfoDigest, 0, $digestToSign, count($RSA_SHA256prefix), count($signedInfoDigest));

        return $this->arrayToBin($digestToSign);
    }

    /**
     * Copy $length elements from source array $a starting at offset $c
     * into destination array $b starting at offset $d.
     *
     * @param array<int, int> $a      Source array
     * @param int             $c      Source offset
     * @param array<int, int> &$b     Destination array (modified in place)
     * @param int             $d      Destination offset
     * @param int             $length Number of elements to copy
     */
    private function systemArrayCopy(
        array $a,
        int $c,
        array &$b,
        int $d,
        int $length
    ): void {
        for ($i = 0; $i < $length; ++$i) {
            $b[$i + $d] = $a[$i + $c];
        }
    }

    /**
     * Pack an array of byte values into a binary string.
     *
     * @param array<int, int> $bytes Array of unsigned byte values (0-255)
     *
     * @return string Binary string
     */
    private function arrayToBin(
        array $bytes
    ): string {
        return call_user_func_array('pack', array_merge(['c*'], $bytes));
    }

    /**
     * Unpack a binary string into an array of unsigned byte values.
     *
     * @param string $bytes Binary string to convert
     *
     * @return array<int, int> Array of byte values (0-255), 1-indexed
     *
     * @throws RuntimeException If unpacking fails
     */
    public function binToArray(
        string $bytes
    ): array {
        $result = unpack('C*', $bytes);
        if (false === $result) {
            throw new RuntimeException('Can not convert bytes to array.');
        }

        return $result;
    }

    /**
     * Calculate the hash digest of an RSA public key from a signature.
     *
     * Formats the key as "<hex(exponent)> <hex(modulus)>" (zero-stripped),
     * then hashes it with the specified algorithm.
     *
     * @param SignatureInterface $signature The signature containing the public key
     * @param string             $algorithm Hash algorithm (default 'sha256')
     *
     * @return string Raw binary hash of the public key
     */
    public function calculatePublicKeyDigest(
        SignatureInterface $signature,
        string $algorithm = 'sha256'
    ): string {
        $rsa = $this->rsaFactory->createPublic($signature->getPublicKey());

        $exponent = $rsa->getExponent()->toHex(true);
        $modulus = $rsa->getModulus()->toHex(true);

        $key = $this->calculateKey($exponent, $modulus);

        return $this->hash($key, $algorithm);
    }

    /**
     * Format a public key string from hex-encoded exponent and modulus.
     *
     * Leading zeros are stripped from both components.
     *
     * @param string $exponent Hex-encoded RSA exponent
     * @param string $modulus  Hex-encoded RSA modulus
     *
     * @return string Formatted string "<exponent> <modulus>"
     */
    public function calculateKey(
        string $exponent,
        string $modulus
    ): string {
        $exponent = ltrim($exponent, '0');
        $modulus = ltrim($modulus, '0');

        return sprintf('%s %s', $exponent, $modulus);
    }

    /**
     * Calculate the X.509 certificate fingerprint.
     *
     * Accepts either PEM-encoded or raw DER certificate content.
     * DER data is automatically converted to PEM format.
     *
     * @param string $certContent PEM or DER certificate content
     * @param string $algorithm   Hash algorithm (default 'sha256')
     * @param bool   $rawOutput   If true, return raw binary; otherwise lowercase hex
     *
     * @return string Certificate fingerprint
     *
     * @throws RuntimeException If fingerprint calculation fails
     */
    public function calculateCertificateFingerprint(
        string $certContent,
        string $algorithm = 'sha256',
        bool $rawOutput = true
    ): string {
        $fingerprint = openssl_x509_fingerprint(
            $this->normalizeCertificateContent($certContent),
            $algorithm,
            $rawOutput
        );
        if (false === $fingerprint) {
            throw new RuntimeException('Can not calculate fingerprint for certificate.');
        }

        return $fingerprint;
    }

    /**
     * Normalize certificate content to PEM format with consistent line endings.
     *
     * If the input is already PEM, normalizes line endings. If it is raw DER,
     * wraps it with PEM header/footer and base64-encodes it.
     *
     * @param string $certContent PEM or DER certificate content
     *
     * @return string PEM-encoded certificate with normalized line endings
     *
     * @throws RuntimeException If line-ending normalization fails
     */
    private function normalizeCertificateContent(string $certContent): string
    {
        if ($this->isPemCertificate($certContent)) {
            $normalizedCert = preg_replace('/\R+/', "\n", trim($certContent));
            if ($normalizedCert === null) {
                throw new RuntimeException('Can not normalize certificate.');
            }

            return $normalizedCert;
        }

        return sprintf(
            "-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----\n",
            chunk_split($this->base64Service->encode($certContent), 64, "\n")
        );
    }

    /**
     * Check whether the given content is already PEM-encoded.
     *
     * @param string $certContent Certificate content to test
     *
     * @return bool True if PEM header and footer markers are present
     */
    private function isPemCertificate(string $certContent): bool
    {
        return str_contains($certContent, '-----BEGIN CERTIFICATE-----')
            && str_contains($certContent, '-----END CERTIFICATE-----');
    }

    /**
     * Generate a random 32-character uppercase hex string (16 bytes of entropy).
     *
     * @return string Hex nonce, e.g. "3A7F0E1C9B2D4F6A..."
     */
    public function generateNonce(): string
    {
        return $this->randomService->hex(32);
    }

    /**
     * Generate a 16-byte random AES transaction key.
     *
     * @return string Raw 16-byte binary key
     */
    public function generateTransactionKey(): string
    {
        return $this->randomService->bytes(16);
    }

    /**
     * Extract the RSA exponent and modulus from a public key as raw byte strings.
     *
     * @param Key $publicKey RSA public key in PEM format
     *
     * @return array{e: string, m: string} Exponent and modulus as raw byte strings
     */
    public function decomposePublicKey(Key $publicKey): array
    {
        $rsa = $this->rsaFactory->createPublic($publicKey);

        return [
            'e' => $rsa->getExponent()->toBytes(),
            'm' => $rsa->getModulus()->toBytes(),
        ];
    }

    /**
     * Generate a random 4-character EBICS order ID.
     *
     * Format: one uppercase letter (A-Z) followed by three alphanumeric characters.
     * Example: "A3F7"
     *
     * @return string 4-character order ID
     */
    public function generateOrderId(): string
    {
        $first = chr(rand(65, 90));
        $num = rand(0, pow(36, 3) - 1);
        $suffix = strtoupper(base_convert((string)$num, 10, 36));
        $suffix = str_pad($suffix, 3, '0', STR_PAD_LEFT);

        return $first . $suffix;
    }

    /**
     * Verify that an RSA private key can be decrypted with the given password.
     *
     * @param Key    $privateKey RSA private key in PEM format
     * @param string $password   Password to attempt decryption with
     *
     * @return bool True if the key loads successfully, false otherwise
     */
    public function checkPrivateKey(Key $privateKey, string $password): bool
    {
        try {
            $this->rsaFactory->createPrivate($privateKey, $password);

            return true;
        } catch (LogicException $exception) {
            return false;
        }
    }

    /**
     * Re-encrypt an RSA key pair with a new password.
     *
     * @param KeyPair $keyPair    The key pair to re-encrypt
     * @param string  $oldPassword Current password
     * @param string  $newPassword New password to apply
     *
     * @return KeyPair New key pair encrypted with the new password
     */
    public function changePrivateKeyPassword(KeyPair $keyPair, string $oldPassword, string $newPassword): KeyPair
    {
        $rsa = $this->rsaFactory->create($keyPair->getPrivateKey()->getType());

        return $rsa->changePassword(
            $keyPair,
            $oldPassword,
            $newPassword
        );
    }
}
