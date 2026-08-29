<?php

namespace EbicsApi\Ebics\Handlers;

use DOMDocument;
use DOMNode;
use EbicsApi\Ebics\Contracts\AuthSignatureHandlerInterface;
use EbicsApi\Ebics\Contracts\Processor\Base64EncoderInterface;
use EbicsApi\Ebics\Handlers\Traits\C14NTrait;
use EbicsApi\Ebics\Handlers\Traits\H00XTrait;
use EbicsApi\Ebics\Models\Keyring;
use EbicsApi\Ebics\Services\CryptService;
use EbicsApi\Ebics\Services\DOMHelper;

/**
 * Class AuthSignatureHandler manage body DOM elements.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 *
 * @internal
 */
abstract class AuthSignatureHandler implements AuthSignatureHandlerInterface
{
    use C14NTrait;
    use H00XTrait;

    public function __construct(
        private readonly Base64EncoderInterface $base64Service,
        private readonly Keyring $keyring,
        private readonly CryptService $cryptService
    ) {
    }

    public function handle(DOMDocument $dom, ?DOMNode $xmlRequestHeader = null): void
    {
        $canonicalizationPath = '//AuthSignature/*';
        $signaturePath = "//*[@authenticate='true']";
        $signatureMethodAlgorithm = 'sha256';
        $digestMethodAlgorithm = 'sha256';
        $canonicalizationMethodAlgorithm = 'REC-xml-c14n-20010315';
        $digestTransformAlgorithm = 'REC-xml-c14n-20010315';
        $ns = $dom->documentElement->lookupNamespaceURI('ds');

        // Add AuthSignature to request.
        $xmlAuthSignature = $dom->createElementNS($dom->documentElement->namespaceURI, 'AuthSignature');

        // Find Header element to insert after.
        if (null === $xmlRequestHeader) {
            $headerList = $this->queryH00XXpath($dom, '//header');
            $item = DOMHelper::safeItem($headerList);
            if (!$item instanceof DOMNode) {
                throw new \LogicException('Header element not found or is not a DOMNode.');
            }
            $xmlRequestHeader = $item;
        }

        $this->insertAfter($xmlAuthSignature, $xmlRequestHeader);

        // Add ds:SignedInfo to AuthSignature.
        $xmlSignedInfo = $dom->createElementNS($ns, 'ds:SignedInfo');
        $xmlAuthSignature->appendChild($xmlSignedInfo);

        // Add ds:CanonicalizationMethod to ds:SignedInfo.
        $xmlCanonicalizationMethod = $dom->createElementNS($ns, 'ds:CanonicalizationMethod');
        $xmlCanonicalizationMethod->setAttribute(
            'Algorithm',
            sprintf('http://www.w3.org/TR/2001/%s', $canonicalizationMethodAlgorithm)
        );
        $xmlSignedInfo->appendChild($xmlCanonicalizationMethod);

        // Add ds:SignatureMethod to ds:SignedInfo.
        $xmlSignatureMethod = $dom->createElementNS($ns, 'ds:SignatureMethod');
        $xmlSignatureMethod->setAttribute(
            'Algorithm',
            sprintf('http://www.w3.org/2001/04/xmldsig-more#rsa-%s', $signatureMethodAlgorithm)
        );
        $xmlSignedInfo->appendChild($xmlSignatureMethod);

        // Add ds:Reference to ds:SignedInfo.
        $xmlReference = $dom->createElementNS($ns, 'ds:Reference');
        $xmlReference->setAttribute('URI', sprintf('#xpointer(%s)', $signaturePath));
        $xmlSignedInfo->appendChild($xmlReference);

        // Add ds:Transforms to ds:Reference.
        $xmlTransforms = $dom->createElementNS($ns, 'ds:Transforms');
        $xmlReference->appendChild($xmlTransforms);

        // Add ds:Transform to ds:Transforms.
        $xmlTransform = $dom->createElementNS($ns, 'ds:Transform');
        $xmlTransform->setAttribute('Algorithm', sprintf('http://www.w3.org/TR/2001/%s', $digestTransformAlgorithm));
        $xmlTransforms->appendChild($xmlTransform);

        // Add ds:DigestMethod to ds:Reference.
        $xmlDigestMethod = $dom->createElementNS($ns, 'ds:DigestMethod');
        $xmlDigestMethod->setAttribute(
            'Algorithm',
            sprintf('http://www.w3.org/2001/04/xmlenc#%s', $digestMethodAlgorithm)
        );
        $xmlReference->appendChild($xmlDigestMethod);

        // Add ds:DigestValue to ds:Reference.
        $xmlDigestValue = $dom->createElementNS($ns, 'ds:DigestValue');
        $canonicalizedHeader = $this->canonicalizeNodeSet(
            DOMHelper::safeItems($this->queryH00XXpath($dom, $signaturePath)),
            false
        );
        $canonicalizedHeaderHash = $this->cryptService->hash($canonicalizedHeader, $digestMethodAlgorithm);
        $digestValueNodeValue = $this->base64Service->encode($canonicalizedHeaderHash);

        $xmlDigestValue->nodeValue = $digestValueNodeValue;
        $xmlReference->appendChild($xmlDigestValue);

        // Add ds:SignatureValue to AuthSignature.
        $xmlSignatureValue = $dom->createElementNS($ns, 'ds:SignatureValue');
        $canonicalizedSignedInfo = $this->calculateC14N(
            DOMHelper::safeItems($this->queryH00XXpath($dom, $canonicalizationPath)),
            $canonicalizationMethodAlgorithm
        );
        $canonicalizedSignedInfoHash = $this->cryptService->hash(
            $canonicalizedSignedInfo,
            $signatureMethodAlgorithm
        );
        $canonicalizedSignedInfoHashEncrypted = $this->cryptService->encrypt(
            $this->keyring->getUserSignatureX()->getPrivateKey(),
            $this->keyring->getPassword(),
            $this->keyring->getUserSignatureXVersion(),
            $canonicalizedSignedInfoHash
        );
        $signatureValueNodeValue = $this->base64Service->encode($canonicalizedSignedInfoHashEncrypted);

        $xmlSignatureValue->nodeValue = $signatureValueNodeValue;
        $xmlAuthSignature->appendChild($xmlSignatureValue);
    }
}
