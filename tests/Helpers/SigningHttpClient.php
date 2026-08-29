<?php

namespace EbicsApi\Ebics\Tests\Helpers;

use DOMElement;
use EbicsApi\Ebics\Contracts\HttpClientInterface;
use EbicsApi\Ebics\Factories\Crypt\RSAFactory;
use EbicsApi\Ebics\Models\Crypt\KeyPair;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Http\Response;
use EbicsApi\Ebics\Services\CryptService;
use EbicsApi\Ebics\Services\Processor\AESEncryptor;
use EbicsApi\Ebics\Services\Processor\Base64Encoder;
use EbicsApi\Ebics\Services\RandomService;
use EbicsApi\Ebics\Services\TransactionKeyResolver;

/**
 * HTTP client decorator that re-signs the authentication signature of
 * responses with the given key pair.
 *
 * Test utility: combined with a faked HTTP client it produces responses
 * whose authentication signature can be verified with the matching public
 * key installed as the bank X002 key in the keyring. This allows the client
 * signature verification to run against faked responses.
 *
 * Previously located in src/Services/SigningHttpClient.php and moved to
 * tests/Helpers as it is test-only (zero-dependency policy for src).
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class SigningHttpClient implements HttpClientInterface
{
    private const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
    private const C14N_ALGORITHM = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';

    private readonly CryptService $cryptService;

    public function __construct(
        private readonly HttpClientInterface $inner,
        private readonly KeyPair $bankKeys,
        private readonly string $password
    ) {
        $aesEncryptor = new AESEncryptor(new TransactionKeyResolver());
        $rsaFactory = new RSAFactory($aesEncryptor);
        $this->cryptService = new CryptService(
            $rsaFactory,
            $aesEncryptor,
            new RandomService(),
            new Base64Encoder()
        );
    }

    /**
     * @inheritDoc
     */
    public function post(string $url, Request $request): Response
    {
        $response = $this->inner->post($url, $request);

        $this->resignAuthSignature($response);

        return $response;
    }

    /**
     * Replace the AuthSignature of the response with one signed by the bank keys.
     */
    private function resignAuthSignature(Response $response): void
    {
        $root = $response->documentElement;
        if (null === $root || 'ebicsHEVResponse' === $root->localName) {
            return;
        }

        foreach ($response->getElementsByTagName('AuthSignature') as $existing) {
            $existing->parentNode->removeChild($existing);
        }

        $header = $response->getElementsByTagName('header')->item(0);
        if (!$header instanceof DOMElement) {
            return;
        }

        $ds = self::XMLDSIG_NS;
        $authSignature = $response->createElementNS($root->namespaceURI, 'AuthSignature');
        $signedInfo = $response->createElementNS($ds, 'ds:SignedInfo');

        $canonicalizationMethod = $response->createElementNS($ds, 'ds:CanonicalizationMethod');
        $canonicalizationMethod->setAttribute('Algorithm', self::C14N_ALGORITHM);
        $signedInfo->appendChild($canonicalizationMethod);

        $signatureMethod = $response->createElementNS($ds, 'ds:SignatureMethod');
        $signatureMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
        $signedInfo->appendChild($signatureMethod);

        $reference = $response->createElementNS($ds, 'ds:Reference');
        $reference->setAttribute('URI', "#xpointer(//*[@authenticate='true'])");

        $transforms = $response->createElementNS($ds, 'ds:Transforms');
        $transform = $response->createElementNS($ds, 'ds:Transform');
        $transform->setAttribute('Algorithm', self::C14N_ALGORITHM);
        $transforms->appendChild($transform);
        $reference->appendChild($transforms);

        $digestMethod = $response->createElementNS($ds, 'ds:DigestMethod');
        $digestMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
        $reference->appendChild($digestMethod);

        $digestValue = $response->createElementNS($ds, 'ds:DigestValue');
        $xpath = new \DOMXPath($response);
        $authenticatedNodes = $xpath->query("//*[@authenticate='true']");
        $selected = [];
        foreach ($authenticatedNodes as $node) {
            if ($node instanceof \DOMNode) {
                $selected[] = $node;
            }
        }
        $authenticated = '';
        foreach ($selected as $node) {
            $nested = false;
            $parent = $node->parentNode;
            while ($parent instanceof \DOMNode) {
                foreach ($selected as $candidate) {
                    if ($candidate->isSameNode($parent)) {
                        $nested = true;
                        break 2;
                    }
                }
                $parent = $parent->parentNode;
            }
            if (!$nested) {
                $authenticated .= $node->C14N(false, false);
            }
        }
        $digestValue->nodeValue = base64_encode(
            $this->cryptService->hash(trim($authenticated), 'sha256')
        );
        $reference->appendChild($digestValue);
        $signedInfo->appendChild($reference);

        $authSignature->appendChild($signedInfo);
        $header->parentNode->insertBefore($authSignature, $header->nextSibling);

        // Canonicalize the attached SignedInfo, sign and attach the value.
        $signatureValue = $response->createElementNS($ds, 'ds:SignatureValue');
        $signatureValue->nodeValue = base64_encode(
            $this->cryptService->encrypt(
                $this->bankKeys->getPrivateKey(),
                $this->password,
                'X002',
                $this->cryptService->hash(trim($signedInfo->C14N(false, false)), 'sha256')
            )
        );
        $authSignature->appendChild($signatureValue);

        $response->loadXML((string)$response->saveXML());
    }
}
