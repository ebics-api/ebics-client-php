<?php

namespace EbicsApi\Ebics\Tests\Services;

use EbicsApi\Ebics\Contracts\SignatureInterface;
use EbicsApi\Ebics\Factories\Crypt\RSAFactory;
use EbicsApi\Ebics\Models\Crypt\Key;
use EbicsApi\Ebics\Models\Crypt\KeyPair;
use EbicsApi\Ebics\Models\Keyring;
use EbicsApi\Ebics\Services\CryptService;
use EbicsApi\Ebics\Services\Processor\AESEncryptor;
use EbicsApi\Ebics\Services\Processor\Base64Encoder;
use EbicsApi\Ebics\Services\RandomService;
use EbicsApi\Ebics\Services\TransactionKeyResolver;
use EbicsApi\Ebics\Tests\AbstractEbicsTestCase;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use RuntimeException;

/**
 * Comprehensive unit tests for CryptService.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 *
 * @group crypt-services
 */
class CryptServiceTest extends AbstractEbicsTestCase
{
    private CryptService $cryptService;
    private RSAFactory $rsaFactory;
    private AESEncryptor $aesEncryptor;
    private RandomService $randomService;

    protected function setUp(): void
    {
        $this->aesEncryptor = new AESEncryptor(new TransactionKeyResolver());
        $this->rsaFactory = new RSAFactory($this->aesEncryptor);
        $this->randomService = new RandomService();
        $this->cryptService = new CryptService($this->rsaFactory, $this->aesEncryptor, $this->randomService, new Base64Encoder());
    }

    public function testHashWithDefaultAlgorithm(): void
    {
        $text = 'test data';
        $hash = $this->cryptService->hash($text);

        self::assertNotEmpty($hash);
        self::assertEquals(32, strlen($hash));
    }

    public function testHashWithHexOutput(): void
    {
        $text = 'test data';
        $hash = $this->cryptService->hash($text, 'sha256', false);

        self::assertNotEmpty($hash);
        self::assertEquals(64, strlen($hash));
        self::assertEquals(hash('sha256', $text), $hash);
    }

    public function testHashWithDifferentAlgorithms(): void
    {
        $text = 'test data';

        $sha1Hash = $this->cryptService->hash($text, 'sha1');
        self::assertEquals(20, strlen($sha1Hash));

        $sha512Hash = $this->cryptService->hash($text, 'sha512');
        self::assertEquals(64, strlen($sha512Hash));
    }

    public function testGenerateKeyPair(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password);

        self::assertInstanceOf(KeyPair::class, $keyPair);
        self::assertObjectHasProperty('privateKey', $keyPair);
        self::assertObjectHasProperty('publicKey', $keyPair);
        self::assertObjectHasProperty('password', $keyPair);
        self::assertEquals($password, $keyPair->getPassword());
    }

    public function testGenerateKeyPairWithCustomParameters(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password, 'sha256', 2048);

        self::assertInstanceOf(KeyPair::class, $keyPair);
        self::assertInstanceOf(Key::class, $keyPair->getPrivateKey());
        self::assertInstanceOf(Key::class, $keyPair->getPublicKey());
    }

    public function testGenerateNonce(): void
    {
        $nonce1 = $this->cryptService->generateNonce();
        $nonce2 = $this->cryptService->generateNonce();

        self::assertEquals(32, strlen($nonce1));
        self::assertMatchesRegularExpression('/^[0-9A-F]{32}$/', $nonce1);
        self::assertNotEquals($nonce1, $nonce2);
    }

    public function testGenerateTransactionKey(): void
    {
        $key1 = $this->cryptService->generateTransactionKey();
        $key2 = $this->cryptService->generateTransactionKey();

        self::assertEquals(16, strlen($key1));
        self::assertNotEquals($key1, $key2);
    }

    public function testGenerateOrderIdFormat(): void
    {
        $orderId = $this->cryptService->generateOrderId();

        self::assertEquals(4, strlen($orderId));
        self::assertMatchesRegularExpression('/^[A-Z]/', $orderId);
        self::assertMatchesRegularExpression('/^[A-Z][0-9A-Z]{3}$/', $orderId);
    }

    public function testGenerateOrderIdUniqueness(): void
    {
        $orderIds = [];
        for ($i = 0; $i < 100; $i++) {
            $orderIds[] = $this->cryptService->generateOrderId();
        }

        $uniqueCount = count(array_unique($orderIds));
        self::assertGreaterThanOrEqual(95, $uniqueCount);
    }

    public function testBinToArray(): void
    {
        $binary = "\x41\x42\x43";
        $array = $this->cryptService->binToArray($binary);

        self::assertIsArray($array);
        self::assertEquals([1 => 65, 2 => 66, 3 => 67], $array);
    }

    public function testCalculateKey(): void
    {
        $exponent = '00010001';
        $modulus = '00C4B1D2E3F4';

        $key = $this->cryptService->calculateKey($exponent, $modulus);

        self::assertEquals('10001 C4B1D2E3F4', $key);
    }

    public function testCalculateKeyRemovesLeadingZeros(): void
    {
        $exponent = '000001';
        $modulus = '0000ABCD';

        $key = $this->cryptService->calculateKey($exponent, $modulus);

        self::assertEquals('1 ABCD', $key);
    }

    public function testCalculateKeyWithNoLeadingZeros(): void
    {
        $exponent = '1234';
        $modulus = 'ABCD';

        $key = $this->cryptService->calculateKey($exponent, $modulus);

        self::assertEquals('1234 ABCD', $key);
    }

    public function testEncryptDecryptRoundtrip(): void
    {
        $key = $this->cryptService->generateTransactionKey();
        $data = 'Sensitive data to encrypt';

        $encrypted = $this->cryptService->encryptByKey($key, $data);
        self::assertNotEmpty($encrypted);

        $decrypted = $this->cryptService->decryptByKey($key, $encrypted);

        self::assertEquals($data, $decrypted);
    }

    public function testDecomposePublicKey(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password);

        $components = $this->cryptService->decomposePublicKey($keyPair->getPublicKey());

        self::assertIsArray($components);
        self::assertArrayHasKey('e', $components);
        self::assertArrayHasKey('m', $components);
        self::assertIsString($components['e']);
        self::assertIsString($components['m']);
        self::assertNotEmpty($components['e']);
        self::assertNotEmpty($components['m']);
    }

    public function testCheckPrivateKeyWithCorrectPassword(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password);

        $isValid = $this->cryptService->checkPrivateKey($keyPair->getPrivateKey(), $password);

        self::assertTrue($isValid);
    }

    public function testCheckPrivateKeyWithWrongPassword(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password);

        $isValid = $this->cryptService->checkPrivateKey($keyPair->getPrivateKey(), 'wrongpassword');

        self::assertFalse($isValid);
    }

    public function testChangePrivateKeyPassword(): void
    {
        $oldPassword = 'oldpassword';
        $newPassword = 'newpassword';

        $keyPair = $this->cryptService->generateKeyPair($oldPassword);

        $newKeyPair = $this->cryptService->changePrivateKeyPassword(
            $keyPair,
            $oldPassword,
            $newPassword
        );

        self::assertInstanceOf(KeyPair::class, $newKeyPair);
        self::assertFalse($this->cryptService->checkPrivateKey($newKeyPair->getPrivateKey(), $oldPassword));
        self::assertTrue($this->cryptService->checkPrivateKey($newKeyPair->getPrivateKey(), $newPassword));
    }

    public function testVerifySignatureRoundtrip(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password);
        $message = 'canonicalized signed info content';

        // Sign like the X002 authentication signature path (PKCS#1 v1.5 over DigestInfo).
        $signature = $this->cryptService->encrypt(
            $keyPair->getPrivateKey(),
            $password,
            SignatureInterface::X_VERSION2,
            $this->cryptService->hash($message)
        );

        self::assertTrue($this->cryptService->verify($keyPair->getPublicKey(), $message, $signature, 'X002'));
    }

    public function testVerifySignatureWithWrongKey(): void
    {
        $password = 'testpassword';
        $signingKeyPair = $this->cryptService->generateKeyPair($password);
        $otherKeyPair = $this->cryptService->generateKeyPair($password);
        $message = 'canonicalized signed info content';

        $signature = $this->cryptService->encrypt(
            $signingKeyPair->getPrivateKey(),
            $password,
            SignatureInterface::X_VERSION2,
            $this->cryptService->hash($message)
        );

        self::assertFalse($this->cryptService->verify($otherKeyPair->getPublicKey(), $message, $signature, 'X002'));
    }

    public function testSignWithA005(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password);
        $data = 'data to sign';

        $signature = $this->cryptService->sign(
            $keyPair->getPrivateKey(),
            $password,
            SignatureInterface::A_VERSION5,
            $data
        );

        self::assertNotEmpty($signature);
        self::assertIsString($signature);
    }

    public function testSignWithA006(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password);
        $data = 'data to sign';

        $signature = $this->cryptService->sign(
            $keyPair->getPrivateKey(),
            $password,
            SignatureInterface::A_VERSION6,
            $data
        );

        self::assertNotEmpty($signature);
        self::assertIsString($signature);
    }

    public function testSignWithUnsupportedVersion(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password);
        $data = 'data to sign';

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Algorithm type for Version A999 not supported');

        $this->cryptService->sign(
            $keyPair->getPrivateKey(),
            $password,
            'A999',
            $data
        );
    }

    public function testEncryptTransactionKey(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password);
        $transactionKey = $this->cryptService->generateTransactionKey();

        $encryptedKey = $this->cryptService->encryptTransactionKey(
            $keyPair->getPublicKey(),
            $transactionKey
        );

        self::assertNotEmpty($encryptedKey);
        self::assertIsString($encryptedKey);
        self::assertNotEquals($transactionKey, $encryptedKey);
    }

    public function testEncryptWithA005(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password);
        $data = 'data to encrypt';

        $encrypted = $this->cryptService->encrypt(
            $keyPair->getPrivateKey(),
            $password,
            SignatureInterface::A_VERSION5,
            $data
        );

        self::assertNotEmpty($encrypted);
        self::assertIsString($encrypted);
    }

    public function testEncryptWithA006(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password);
        $data = 'data to encrypt';

        $encrypted = $this->cryptService->encrypt(
            $keyPair->getPrivateKey(),
            $password,
            SignatureInterface::A_VERSION6,
            $data
        );

        self::assertNotEmpty($encrypted);
        self::assertIsString($encrypted);
    }

    public function testCalculateCertificateFingerprint(): void
    {
        $dn = [
            "countryName" => "US",
            "stateOrProvinceName" => "Test",
            "localityName" => "Test",
            "organizationName" => "Test",
            "commonName" => "test.example.com"
        ];

        $privkey = openssl_pkey_new();
        if ($privkey === false) {
            self::markTestSkipped('Cannot generate test certificate');
        }

        $csr = openssl_csr_new($dn, $privkey);
        if ($csr === false) {
            self::markTestSkipped('Cannot generate test certificate');
        }

        $cert = openssl_csr_sign($csr, null, $privkey, 365);
        if ($cert === false) {
            self::markTestSkipped('Cannot generate test certificate');
        }

        openssl_x509_export($cert, $certContent);

        $fingerprint = $this->cryptService->calculateCertificateFingerprint(
            $certContent,
            'sha256',
            true
        );

        self::assertNotEmpty($fingerprint);
        self::assertEquals(32, strlen($fingerprint));

        $fingerprintHex = $this->cryptService->calculateCertificateFingerprint(
            $certContent,
            'sha256',
            false
        );

        self::assertNotEmpty($fingerprintHex);
        self::assertEquals(64, strlen($fingerprintHex));
    }

    public function testCalculateCertificateFingerprintWithInvalidCert(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Can not calculate fingerprint for certificate.');

        @$this->cryptService->calculateCertificateFingerprint(
            'invalid certificate content',
            'sha256',
            true
        );
    }

    public function testDecryptOrderDataCompressedWithoutSignatureE(): void
    {
        $keyring = new Keyring(Keyring::VERSION_25);
        $keyring->setPassword('testpassword');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Signature E is not set.');

        $this->cryptService->decryptOrderDataCompressed(
            $keyring,
            'encrypted_data',
            'encrypted_transaction_key'
        );
    }

    public function testDecryptOrderDataCompressedWithoutPrivateKey(): void
    {
        $keyring = new Keyring(Keyring::VERSION_25);
        $keyring->setPassword('testpassword');

        $publicKey = new Key('-----BEGIN PUBLIC KEY-----', 1);
        $signature = new \EbicsApi\Ebics\Models\Signature('E', $publicKey, null);
        $keyring->setUserSignatureE($signature);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Signature E private key is not set.');

        $this->cryptService->decryptOrderDataCompressed(
            $keyring,
            'encrypted_data',
            'encrypted_transaction_key'
        );
    }

    public function testDecryptOrderDataCompressedHappyPath(): void
    {
        $password = 'test_password';
        $orderData = 'This is the order data payload to encrypt and decrypt.';
        $keyring = new Keyring(Keyring::VERSION_25);
        $keyring->setPassword($password);

        $keyPair = $this->cryptService->generateKeyPair($password);

        $aesKey = $this->cryptService->generateTransactionKey();
        $encryptedTransactionKey = $this->cryptService->encryptTransactionKey(
            $keyPair->getPublicKey(),
            $aesKey
        );

        $encryptedOrderData = $this->cryptService->encryptByKey($aesKey, $orderData);

        $signature = new \EbicsApi\Ebics\Models\Signature(
            \EbicsApi\Ebics\Contracts\SignatureInterface::TYPE_E,
            $keyPair->getPublicKey(),
            $keyPair->getPrivateKey()
        );
        $keyring->setUserSignatureE($signature);

        $decrypted = $this->cryptService->decryptOrderDataCompressed(
            $keyring,
            $encryptedOrderData,
            $encryptedTransactionKey
        );

        self::assertEquals($orderData, $decrypted);
    }

    public function testCalculatePublicKeyDigest(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password);

        $publicKey = $keyPair->getPublicKey();
        $signature = new \EbicsApi\Ebics\Models\Signature(
            \EbicsApi\Ebics\Contracts\SignatureInterface::TYPE_E,
            $publicKey,
            $keyPair->getPrivateKey()
        );

        $digest = $this->cryptService->calculatePublicKeyDigest($signature);

        self::assertNotEmpty($digest);
        self::assertEquals(32, strlen($digest));
    }

    public function testCalculatePublicKeyDigestWithDifferentAlgorithms(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password);

        $signature = new \EbicsApi\Ebics\Models\Signature(
            \EbicsApi\Ebics\Contracts\SignatureInterface::TYPE_E,
            $keyPair->getPublicKey(),
            $keyPair->getPrivateKey()
        );

        $sha256 = $this->cryptService->calculatePublicKeyDigest($signature, 'sha256');
        $sha512 = $this->cryptService->calculatePublicKeyDigest($signature, 'sha512');

        self::assertEquals(32, strlen($sha256));
        self::assertEquals(64, strlen($sha512));
        self::assertNotEquals($sha256, $sha512);
    }

    public function testCalculatePublicKeyDigestIsConsistent(): void
    {
        $password = 'testpassword';
        $keyPair = $this->cryptService->generateKeyPair($password);

        $signature = new \EbicsApi\Ebics\Models\Signature(
            \EbicsApi\Ebics\Contracts\SignatureInterface::TYPE_E,
            $keyPair->getPublicKey(),
            $keyPair->getPrivateKey()
        );

        $digest1 = $this->cryptService->calculatePublicKeyDigest($signature);
        $digest2 = $this->cryptService->calculatePublicKeyDigest($signature);

        self::assertEquals($digest1, $digest2);
    }

    private function generateTestCertificate(): ?string
    {
        $dn = [
            "countryName" => "US",
            "stateOrProvinceName" => "Test",
            "localityName" => "Test",
            "organizationName" => "Test",
            "commonName" => "test.example.com"
        ];

        $privkey = openssl_pkey_new();
        if ($privkey === false) {
            return null;
        }

        $csr = openssl_csr_new($dn, $privkey);
        if ($csr === false) {
            return null;
        }

        $cert = openssl_csr_sign($csr, null, $privkey, 365);
        if ($cert === false) {
            return null;
        }

        openssl_x509_export($cert, $certContent);

        return $certContent;
    }

    public static function malformedCertificateFormatsProvider(): array
    {
        return [
            'crlf_line_endings' => [
                static fn (string $pem): string => str_replace("\n", "\r\n", $pem),
            ],
            'cr_line_endings' => [
                static fn (string $pem): string => str_replace("\n", "\r", $pem),
            ],
            'empty_lines_between' => [
                static fn (string $pem): string => str_replace("\n", "\n\n", $pem),
            ],
            'leading_trailing_whitespace' => [
                static fn (string $pem): string => "   \n  " . $pem . "  \n   ",
            ],
        ];
    }

    #[DataProvider('malformedCertificateFormatsProvider')]
    #[Group('crypt-services')]
    public function testCalculateCertificateFingerprintNormalizesPem(callable $transform): void
    {
        $certContent = $this->generateTestCertificate();

        if ($certContent === null) {
            self::markTestSkipped('Cannot generate test certificate');
        }

        $malformedCert = $transform($certContent);

        self::assertNotEquals(
            $certContent,
            $malformedCert,
            'The transformation should produce a malformed certificate'
        );

        $expectedFingerprint = $this->cryptService->calculateCertificateFingerprint(
            $certContent,
            'sha256',
            false
        );

        $actualFingerprint = $this->cryptService->calculateCertificateFingerprint(
            $malformedCert,
            'sha256',
            false
        );

        self::assertEquals($expectedFingerprint, $actualFingerprint);
    }

    public function testCalculateCertificateFingerprintSupportsDerInput(): void
    {
        $certContent = $this->generateTestCertificate();

        if ($certContent === null) {
            self::markTestSkipped('Cannot generate test certificate');
        }

        $derContent = $this->convertPemToDer($certContent);
        self::assertNotEmpty($derContent);

        $expectedFingerprint = hash('sha256', $derContent);
        $actualFingerprint = $this->cryptService->calculateCertificateFingerprint(
            $derContent,
            'sha256',
            false
        );

        self::assertSame($expectedFingerprint, $actualFingerprint);
    }

    private function convertPemToDer(string $certContent): string
    {
        $normalizedCert = preg_replace(
            '/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\R/',
            '',
            $certContent
        );
        if ($normalizedCert === null) {
            self::fail('Cannot normalize PEM certificate.');
        }

        $derContent = base64_decode($normalizedCert, true);
        if ($derContent === false) {
            self::fail('Cannot decode PEM certificate.');
        }

        return $derContent;
    }
}
