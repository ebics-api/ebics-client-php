<?php

namespace EbicsApi\Ebics\Tests\Services;

use EbicsApi\Ebics\Contracts\HttpClientInterface;
use EbicsApi\Ebics\Exceptions\SignatureEbicsException;
use EbicsApi\Ebics\Factories\Crypt\RSAFactory;
use EbicsApi\Ebics\Factories\EbicsFactoryV25;
use EbicsApi\Ebics\Factories\SegmentFactory;
use EbicsApi\Ebics\Factories\SignatureFactory;
use EbicsApi\Ebics\Handlers\Traits\H004Trait;
use EbicsApi\Ebics\Handlers\Traits\H00XTrait;
use EbicsApi\Ebics\Models\Crypt\KeyPair;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Http\Response;
use EbicsApi\Ebics\Models\Keyring;
use EbicsApi\Ebics\Services\CryptService;
use EbicsApi\Ebics\Services\FakerHttpClient;
use EbicsApi\Ebics\Services\Processor\AESEncryptor;
use EbicsApi\Ebics\Services\Processor\Base64Encoder;
use EbicsApi\Ebics\Services\Processor\ZipCompressor;
use EbicsApi\Ebics\Services\RandomService;
use EbicsApi\Ebics\Services\TransactionKeyResolver;
use EbicsApi\Ebics\Tests\AbstractEbicsTestCase;
use EbicsApi\Ebics\Tests\Helpers\SigningHttpClient;

/**
 * Test re-signing of faked responses for signature verification.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 *
 * @group signing-http-client
 */
class SigningHttpClientTest extends AbstractEbicsTestCase
{
    use H00XTrait;
    use H004Trait;

    public function testResignedResponsePassesVerification(): void
    {
        $bankKeys = $this->createBankKeys();
        $client = new SigningHttpClient(
            new FakerHttpClient($this->fixtures),
            $bankKeys,
            'mysecret'
        );

        $response = $client->post('https://localhost', $this->createSprRequest());

        $keyring = new Keyring(Keyring::VERSION_25);
        $signatureFactory = new SignatureFactory(new RSAFactory(new AESEncryptor(new TransactionKeyResolver())));
        $keyring->setBankSignatureX($signatureFactory->createSignatureXFromKeys($bankKeys));

        $cryptService = new CryptService(
            new RSAFactory(new AESEncryptor(new TransactionKeyResolver())),
            new AESEncryptor(new TransactionKeyResolver()),
            new RandomService(),
            new Base64Encoder()
        );
        $responseHandler = (new EbicsFactoryV25())->createResponseHandler(
            new SegmentFactory(),
            $cryptService,
            new ZipCompressor(),
            new Base64Encoder()
        );

        // The SPR fixture contains an AuthSignature that gets re-signed.
        $responseHandler->verifyAuthSignature($response, $keyring);

        // No exception means that the verification passed.
        $this->addToAssertionCount(1);
    }

    public function testTamperedResignedResponseFailsVerification(): void
    {
        $bankKeys = $this->createBankKeys();
        $client = new SigningHttpClient(
            new FakerHttpClient($this->fixtures),
            $bankKeys,
            'mysecret'
        );

        $response = $client->post('https://localhost', $this->createSprRequest());
        $xpath = new \DOMXPath($response);
        $xpath->registerNamespace('H004', 'urn:org:ebics:H004');
        $reportText = $xpath->query('//H004:ReportText')->item(0);
        self::assertNotNull($reportText);
        $reportText->nodeValue = '[EBICS_TAMPERED] Tampered.';

        $keyring = new Keyring(Keyring::VERSION_25);
        $signatureFactory = new SignatureFactory(new RSAFactory(new AESEncryptor(new TransactionKeyResolver())));
        $keyring->setBankSignatureX($signatureFactory->createSignatureXFromKeys($bankKeys));

        $cryptService = new CryptService(
            new RSAFactory(new AESEncryptor(new TransactionKeyResolver())),
            new AESEncryptor(new TransactionKeyResolver()),
            new RandomService(),
            new Base64Encoder()
        );
        $responseHandler = (new EbicsFactoryV25())->createResponseHandler(
            new SegmentFactory(),
            $cryptService,
            new ZipCompressor(),
            new Base64Encoder()
        );

        $this->expectException(SignatureEbicsException::class);

        $responseHandler->verifyAuthSignature($response, $keyring);
    }

    private function createSprRequest(): Request
    {
        $request = new Request();
        $request->loadXML(
            '<ebicsRequest xmlns="urn:org:ebics:H004">'
            . '<header><static><OrderType>SPR</OrderType></static></header>'
            . '<body/>'
            . '</ebicsRequest>'
        );

        return $request;
    }

    private function createBankKeys(): KeyPair
    {        $keys = json_decode((string)file_get_contents($this->fixtures . '/keys.json'));
        $rsaFactory = new RSAFactory(new AESEncryptor(new TransactionKeyResolver()));
        $rsa = $rsaFactory->createPrivate(
            new \EbicsApi\Ebics\Models\Crypt\Key($keys->X002, \EbicsApi\Ebics\Models\Crypt\RSA::PRIVATE_FORMAT_PKCS1),
            'mysecret'
        );

        return new KeyPair(
            new \EbicsApi\Ebics\Models\Crypt\Key(
                (string)$rsa->getPublicKey(\EbicsApi\Ebics\Models\Crypt\RSA::PUBLIC_FORMAT_PKCS1),
                \EbicsApi\Ebics\Models\Crypt\RSA::PUBLIC_FORMAT_PKCS1
            ),
            new \EbicsApi\Ebics\Models\Crypt\Key($keys->X002, \EbicsApi\Ebics\Models\Crypt\RSA::PRIVATE_FORMAT_PKCS1),
            'mysecret'
        );
    }
}
