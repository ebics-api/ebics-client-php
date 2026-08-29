<?php

namespace EbicsApi\Ebics\Tests;

use EbicsApi\Ebics\Contracts\EbicsClientInterface;
use EbicsApi\Ebics\Contracts\LoggerInterface;
use EbicsApi\Ebics\Contracts\SignatureInterface;
use EbicsApi\Ebics\Contracts\X509GeneratorInterface;
use EbicsApi\Ebics\EbicsClient;
use EbicsApi\Ebics\Factories\Crypt\RSAFactory;
use EbicsApi\Ebics\Factories\SignatureFactory;
use EbicsApi\Ebics\Factories\Crypt\X509Factory;
use EbicsApi\Ebics\Models\Bank;
use EbicsApi\Ebics\Models\Crypt\Key;
use EbicsApi\Ebics\Models\Crypt\KeyPair;
use EbicsApi\Ebics\Models\Crypt\RSA;
use EbicsApi\Ebics\Models\CustomerCreditTransfer;
use EbicsApi\Ebics\Models\CustomerDirectDebit;
use EbicsApi\Ebics\Models\EbicsClientOptions;
use EbicsApi\Ebics\Models\Keyring;
use EbicsApi\Ebics\Models\User;
use EbicsApi\Ebics\Models\X509\BankX509Generator;
use EbicsApi\Ebics\Services\DebuggerHttpClient;
use EbicsApi\Ebics\Services\FakerHttpClient;
use EbicsApi\Ebics\Services\FileKeyringManager;
use EbicsApi\Ebics\Services\Processor\AESEncryptor;
use EbicsApi\Ebics\Services\TransactionKeyResolver;
use EbicsApi\Ebics\Tests\Helpers\SigningHttpClient;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Class TestCase extends basic TestCase for add extra setups.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
abstract class AbstractEbicsTestCase extends TestCase
{
    protected $data = __DIR__ . '/_data';

    protected $fixtures = __DIR__ . '/_fixtures';

    protected $schema = __DIR__ . '/../doc/schema';

    protected function setupClientV24(
        int $credentialsId,
        bool $fake = false,
        bool $debug = false,
        ?LoggerInterface $logger = null
    ): EbicsClientInterface {
        return $this->setupClient(Keyring::VERSION_24, $credentialsId, $fake, $debug, $logger);
    }

    protected function setupClientV25(
        int $credentialsId,
        bool $fake = false,
        bool $debug = false,
        ?LoggerInterface $logger = null
    ): EbicsClientInterface {
        return $this->setupClient(Keyring::VERSION_25, $credentialsId, $fake, $debug, $logger);
    }

    protected function setupClientV30(
        int $credentialsId,
        bool $fake = false,
        bool $debug = false,
        ?LoggerInterface $logger = null
    ): EbicsClientInterface {
        return $this->setupClient(Keyring::VERSION_30, $credentialsId, $fake, $debug, $logger);
    }

    private function setupClient(
        string $version,
        int $credentialsId,
        bool $fake = false,
        bool $debug = false,
        ?LoggerInterface $logger = null
    ): EbicsClientInterface {
        $credentials = $this->credentialsDataProvider($credentialsId);

        $bank = new Bank($credentials['hostId'], $credentials['hostURL']);
        $bank->setServerName(sprintf('Server %d', $credentialsId));
        $bank->setCountryCode($credentials['countryCode']);
        $user = new User($credentials['partnerId'], $credentials['userId']);

        $keyringManager = new FileKeyringManager();

        $keyringPath = sprintf('%s/workspace/keyring_%d.json', $this->data, $credentialsId);
        if (is_file($keyringPath)) {
            $keyring = $keyringManager->loadKeyring($keyringPath, $credentials['password'], $version);
        } else {
            $keyring = $keyringManager->createKeyring($version);
            $keyring->setPassword($credentials['password']);
        }

        $options = new EbicsClientOptions();
        if (true === $fake) {
            // Re-sign faked responses with a known bank key pair and install
            // the matching public key, so that the client signature
            // verification runs against the faked responses.
            $bankKeys = $this->createFakeBankKeys();
            $keyring->setBankSignatureX($this->createFakeBankSignature($bankKeys));
            $options->setHttpClient(new SigningHttpClient(
                new FakerHttpClient($this->fixtures),
                $bankKeys,
                'mysecret'
            ));
        }
        if (true === $debug) {
            $options->setHttpClient(new DebuggerHttpClient());
        }

        $options->setSchemaDir($this->schema);

        if (null !== $logger) {
            $options->setLogger($logger);
        }

        $options->setCurlOptions([
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_SSL_VERIFYPEER => false,
        ]);

        $ebicsClient = new EbicsClient($bank, $user, $keyring, $options);

        if ($credentials['hostIsCertified']) {
            $x509Generator = new BankX509Generator();
            $x509Generator->setCertificateOptionsByBank($bank);
            $keyring->setCertificateGenerator($x509Generator);
        }

        if (!is_file($keyringPath)) {
            $ebicsClient->createUserSignatures(['a_version' => $credentials['aVersion']]);
            $this->saveKeyring($credentialsId, $ebicsClient->getKeyring());
        }

        return $ebicsClient;
    }

    protected function loadKeyring(string $keyringPath, string $password, string $version): Keyring
    {
        $keyringManager = new FileKeyringManager();

        return $keyringManager->loadKeyring($keyringPath, $password, $version);
    }

    /**
     * Deterministic key pair playing the bank role for faked responses.
     */
    private function createFakeBankKeys(): KeyPair
    {
        $keys = json_decode((string)file_get_contents($this->fixtures . '/keys.json'));
        $rsaFactory = new RSAFactory(new AESEncryptor(new TransactionKeyResolver()));
        $rsa = $rsaFactory->createPrivate(
            new Key($keys->X002, RSA::PRIVATE_FORMAT_PKCS1),
            'mysecret'
        );

        return new KeyPair(
            new Key((string)$rsa->getPublicKey(RSA::PUBLIC_FORMAT_PKCS1), RSA::PUBLIC_FORMAT_PKCS1),
            new Key($keys->X002, RSA::PRIVATE_FORMAT_PKCS1),
            'mysecret'
        );
    }

    private function createFakeBankSignature(KeyPair $bankKeys): SignatureInterface
    {
        $signatureFactory = new SignatureFactory(
            new RSAFactory(new AESEncryptor(new TransactionKeyResolver()))
        );

        return $signatureFactory->createSignatureXFromKeys($bankKeys);
    }

    protected function saveKeyring(int $credentialsId, Keyring $keyring): void
    {
        $keyringRealPath = sprintf('%s/workspace/keyring_%d.json', $this->data, $credentialsId);
        $keyringManager = new FileKeyringManager();
        $keyringManager->saveKeyring($keyring, $keyringRealPath);
    }

    protected function setupKeys(Keyring $keyring)
    {
        $keys = json_decode(file_get_contents($this->fixtures . '/keys.json'));
        $keyring->setPassword('mysecret');
        $signatureFactory = new SignatureFactory(new RSAFactory(new AESEncryptor(new TransactionKeyResolver())));

        $userSignatureA = $signatureFactory->createSignatureA(
            $keyring->getUserSignatureA()->getPublicKey(),
            new Key($keys->A006, RSA::PRIVATE_FORMAT_PKCS1)
        );
        $userSignatureA->setCertificateContent($keyring->getUserSignatureA()->getCertificateContent());
        $keyring->setUserSignatureA($userSignatureA);

        $userSignatureE = $signatureFactory->createSignatureE(
            $keyring->getUserSignatureE()->getPublicKey(),
            new Key($keys->E002, RSA::PRIVATE_FORMAT_PKCS1)
        );
        $userSignatureE->setCertificateContent($keyring->getUserSignatureE()->getCertificateContent());
        $keyring->setUserSignatureE($userSignatureE);

        $userSignatureX = $signatureFactory->createSignatureX(
            $keyring->getUserSignatureX()->getPublicKey(),
            new Key($keys->X002, RSA::PRIVATE_FORMAT_PKCS1)
        );
        $userSignatureX->setCertificateContent($keyring->getUserSignatureX()->getCertificateContent());
        $keyring->setUserSignatureX($userSignatureX);
    }

    protected function setupIssuer(X509GeneratorInterface $x509Generator, array $issuer, string $password): void
    {
        $rsaFactory = new RSAFactory(new AESEncryptor(new TransactionKeyResolver()));
        $x509Factory = new X509Factory();
        $x509 = $x509Factory->create();
        $x509->loadX509($issuer['certificate']);
        $x509Context = $x509Generator->getAX509Context();
        $x509Context->setIssuerPublicKey(
            $rsaFactory->createPublic(new Key($issuer['publickey'], $issuer['publickey_type']))
        );
        $x509Context->setIssuerPrivateKey(
            $rsaFactory->createPrivate(
                new Key($issuer['privatekey'], $issuer['privatekey_type']),
                $password
            )
        );
        $x509Context->applyIssuerDN($x509);
    }

    /**
     * Validate response data is Ok.
     *
     * @param string $code
     * @param string $reportText
     *
     * @return void
     */
    protected function assertResponseOk(string $code, string $reportText)
    {
        self::assertEquals('000000', $code, $reportText);
    }

    /**
     * Validate response data is Done.
     *
     * @param string $code
     * @param string $reportText
     *
     * @return void
     */
    protected function assertResponseDone(string $code, string $reportText)
    {
        self::assertEquals('011000', $code, $reportText);
    }

    protected function assertExceptionCode(?string $code = null)
    {
        if (null !== $code) {
            $code = (int)$code;
            $this->expectExceptionCode($code);
        }
    }

    /**
     * Client credentials data provider.
     *
     * @param int $credentialsId
     *
     * @return array
     */
    public function credentialsDataProvider(int $credentialsId): array
    {
        $path = sprintf('%s/credentials/credentials_%d.json', $this->data, $credentialsId);

        if (!file_exists($path)) {
            throw new RuntimeException('Credentials missing');
        }

        $credentialsEnc = json_decode(file_get_contents($path), true);

        return [
            'hostId' => $credentialsEnc['hostId'],
            'hostURL' => $credentialsEnc['hostURL'],
            'countryCode' => $credentialsEnc['countryCode'],
            'hostIsCertified' => (bool)$credentialsEnc['hostIsCertified'],
            'partnerId' => $credentialsEnc['partnerId'],
            'userId' => $credentialsEnc['userId'],
            'aVersion' => $credentialsEnc['aVersion'],
            'password' => $credentialsEnc['password'],
        ];
    }

    /**
     * Create simple instance of CustomerCreditTransfer.
     */
    protected function buildCustomerCreditTransfer(): CustomerCreditTransfer
    {
        $xml = new CustomerCreditTransfer();

        $xml->loadXML(file_get_contents($this->fixtures . '/pain.001.001.12.xml'));

        return $xml;
    }

    /**
     * Create simple instance of CustomerDirectDebit.
     */
    protected function buildCustomerDirectDebit(): CustomerDirectDebit
    {
        $xml = new CustomerDirectDebit();

        $xml->loadXML(file_get_contents($this->fixtures . '/pain.000.001.11.xml'));

        return $xml;
    }
}
