<?php

namespace EbicsApi\Ebics\Handlers;

use DateTimeInterface;
use DOMElement;
use EbicsApi\Ebics\Contracts\SignatureInterface;
use EbicsApi\Ebics\Handlers\Traits\H005Trait;
use EbicsApi\Ebics\Models\Crypt\X509;
use EbicsApi\Ebics\Models\XmlData;
use EbicsApi\Ebics\Models\XmlDocument;
use EbicsApi\Ebics\Services\DOMHelper;
use RuntimeException;

/**
 * Ebics 3.0 OrderDataHandler.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 *
 * @internal
 */
final class OrderDataHandlerV30 extends OrderDataHandler
{
    use H005Trait;

    public function handleSignaturePubKey(
        DOMElement $xmlSignaturePubKeyInfo,
        XmlData $xml,
        SignatureInterface $certificateA,
        ?DateTimeInterface $dateTime,
        ?string $ns = null
    ): void {
        // Is not need for V3.
    }

    public function handleAuthenticationPubKey(
        DOMElement $xmlAuthenticationPubKeyInfo,
        XmlData $xml,
        SignatureInterface $certificateX,
        ?DateTimeInterface $dateTime,
        ?string $ns = null
    ): void {
        // Is not need for V3.
    }

    public function handleEncryptionPubKey(
        DOMElement $xmlEncryptionPubKeyInfo,
        XmlData $xml,
        SignatureInterface $certificateE,
        ?DateTimeInterface $dateTime,
        ?string $ns = null
    ): void {
        // Is not need for V3.
    }

    public function retrieveAuthenticationSignature(XmlDocument $document): SignatureInterface
    {
        $h00x = $this->getH00XVersion();
        $xpath = $this->prepareH00XXPath($document);

        $x509Certificate = $xpath->query("//$h00x:AuthenticationPubKeyInfo/ds:X509Data/ds:X509Certificate");
        $x509CertificateValue = DOMHelper::safeItemValueOrNull($x509Certificate);
        $x509CertificateValueDe = $this->base64Service->decode($x509CertificateValue);

        if (null === $x509CertificateValue) {
            throw new RuntimeException('EBICS 3.0 is not supported for not certified banks.');
        }

        $certificateContent
            = "-----BEGIN CERTIFICATE-----\n" .
            chunk_split($x509CertificateValue, 64) .
            "-----END CERTIFICATE-----\n";

        $x509 = new X509();
        $x509->loadX509($x509CertificateValueDe);

        $publicKey = $x509->getPublicKey();

        $signature = $this->signatureFactory->createSignatureXFromDetails(
            $publicKey->getModulus(),
            $publicKey->getExponent()
        );

        $signature->setCertificateContent($certificateContent);

        return $signature;
    }

    public function retrieveEncryptionSignature(XmlDocument $document): SignatureInterface
    {
        $h00x = $this->getH00XVersion();
        $xpath = $this->prepareH00XXPath($document);

        $x509Certificate = $xpath->query("//$h00x:EncryptionPubKeyInfo/ds:X509Data/ds:X509Certificate");
        $x509CertificateValue = DOMHelper::safeItemValueOrNull($x509Certificate);
        $x509CertificateValueDe = $this->base64Service->decode($x509CertificateValue);

        if (null === $x509CertificateValue) {
            throw new RuntimeException('EBICS 3.0 is not supported for not certified banks.');
        }

        $certificateContent
            = "-----BEGIN CERTIFICATE-----\n" .
            chunk_split($x509CertificateValue, 64) .
            "-----END CERTIFICATE-----\n";

        $x509 = new X509();
        $x509->loadX509($x509CertificateValueDe);

        $publicKey = $x509->getPublicKey();

        $signature = $this->signatureFactory->createSignatureEFromDetails(
            $publicKey->getModulus(),
            $publicKey->getExponent()
        );

        $signature->setCertificateContent($certificateContent);

        return $signature;
    }
}
