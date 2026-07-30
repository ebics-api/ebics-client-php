<?php

namespace EbicsApi\Ebics\Orders;

use EbicsApi\Ebics\Builders\Request\BodyBuilder;
use EbicsApi\Ebics\Builders\Request\DataTransferBuilder;
use EbicsApi\Ebics\Builders\Request\HeaderBuilder;
use EbicsApi\Ebics\Builders\Request\OrderDetailsBuilder;
use EbicsApi\Ebics\Builders\Request\RootBuilder;
use EbicsApi\Ebics\Builders\Request\StaticBuilder;
use EbicsApi\Ebics\Contexts\RequestContext;
use EbicsApi\Ebics\Contracts\SignatureInterface;
use EbicsApi\Ebics\Models\Customer;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Order\StandardOrder;
use EbicsApi\Ebics\Models\Order\StandardOrderResult;
use EbicsApi\Ebics\Models\UserSignature;

/**
 * Make H3K request.
 * Send to the bank public signatures of signature (A005|A006), authentication (X002) and encryption (E002).
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class H3K extends StandardOrder
{
    private SignatureInterface $signatureA;
    private SignatureInterface $signatureE;
    private SignatureInterface $signatureX;

    public function __construct(?RequestContext $context = null)
    {
        $this->context = $context;
    }

    public function createRequest(): Request
    {
        $this->signatureA = $this->context->getKeyring()->getUserSignatureA();
        $this->signatureE = $this->context->getKeyring()->getUserSignatureE();
        $this->signatureX = $this->context->getKeyring()->getUserSignatureX();

        return $this->buildRequest();
    }

    public function afterExecute(StandardOrderResult $orderResult): void
    {
        $this->context->getKeyring()->setUserSignatureA($this->signatureA);
        $this->context->getKeyring()->setUserSignatureE($this->signatureE);
        $this->context->getKeyring()->setUserSignatureX($this->signatureX);
    }

    private function buildRequest(): Request
    {
        $orderData = $this->createOrderData();

        $signatureData = new UserSignature();
        $this->userSignatureHandler->handle(
            $signatureData,
            $this->orderDataHandler->hash($orderData->getContent())
        );

        $this->context
            ->setOrderType('H3K')
            ->setOrderData($orderData->getContent())
            ->setSignatureData($signatureData);

        return $this->requestFactory
            ->createRequestBuilderInstance()
            ->addContainerUnsigned(function (RootBuilder $builder) {
                $builder->addHeader(function (HeaderBuilder $builder) {
                    $builder->addStatic(function (StaticBuilder $builder) {
                        $builder
                            ->addHostId($this->context->getBank()->getHostId())
                            ->addPartnerId($this->context->getUser()->getPartnerId())
                            ->addUserId($this->context->getUser()->getUserId())
                            ->addProduct($this->context->getProduct(), $this->context->getLanguage())
                            ->addOrderDetails(function (OrderDetailsBuilder $orderDetailsBuilder) {
                                $this->requestFactory->addOrderType(
                                    $orderDetailsBuilder,
                                    $this->context->getOrderType(),
                                    $this->context->isWithES() ?
                                        OrderDetailsBuilder::ORDER_ATTRIBUTE_OZHNN :
                                        OrderDetailsBuilder::ORDER_ATTRIBUTE_DZHNN
                                );
                            })
                            ->addSecurityMedium(StaticBuilder::SECURITY_MEDIUM_0000);
                    })->addMutable();
                })->addBody(function (BodyBuilder $builder) {
                    $builder->addDataTransfer(function (DataTransferBuilder $builder) {
                        $builder->addSignatureData($this->context->getSignatureData(), '');
                        $builder->addOrderData($this->context->getOrderData());
                    });
                });
            })
            ->popInstance();
    }

    public function createOrderData(): Customer
    {
        $xml = new Customer();

        // Add H3KRequestOrderData to root.
        $xmlH3KRequestOrderData = $xml->createElementNS(
            $this->orderDataHandler->getH00XNamespace(),
            'H3KRequestOrderData'
        );
        $xmlH3KRequestOrderData->setAttributeNS(
            'http://www.w3.org/2000/xmlns/',
            'xmlns:ds',
            'http://www.w3.org/2000/09/xmldsig#'
        );

        $xml->appendChild($xmlH3KRequestOrderData);

        // Add SignatureCertificateInfo to H3KRequestOrderData.
        $xmlSignatureCertificateInfo = $xml->createElement('SignatureCertificateInfo');
        $xmlH3KRequestOrderData->appendChild($xmlSignatureCertificateInfo);
        $this->orderDataHandler->handleX509Data($xmlSignatureCertificateInfo, $xml, $this->signatureA);

        // Add EncryptionVersion to EncryptionPubKeyInfo.
        $xmlSignatureVersion = $xml->createElement('SignatureVersion');
        $xmlSignatureVersion->nodeValue = $this->context->getKeyring()->getUserSignatureAVersion();
        $xmlSignatureCertificateInfo->appendChild($xmlSignatureVersion);

        // Add AuthenticationCertificateInfo to H3KRequestOrderData.
        $xmlAuthenticationCertificateInfo = $xml->createElement('AuthenticationCertificateInfo');
        $xmlH3KRequestOrderData->appendChild($xmlAuthenticationCertificateInfo);
        $this->orderDataHandler->handleX509Data($xmlAuthenticationCertificateInfo, $xml, $this->signatureX);

        // Add EncryptionVersion to EncryptionPubKeyInfo.
        $xmlAuthenticationVersion = $xml->createElement('AuthenticationVersion');
        $xmlAuthenticationVersion->nodeValue = $this->context->getKeyring()->getUserSignatureXVersion();
        $xmlAuthenticationCertificateInfo->appendChild($xmlAuthenticationVersion);

        // Add EncryptionCertificateInfo to H3KRequestOrderData.
        $xmlEncryptionCertificateInfo = $xml->createElement('EncryptionCertificateInfo');
        $xmlH3KRequestOrderData->appendChild($xmlEncryptionCertificateInfo);
        $this->orderDataHandler->handleX509Data($xmlEncryptionCertificateInfo, $xml, $this->signatureE);

        // Add EncryptionVersion to EncryptionPubKeyInfo.
        $xmlEncryptionVersion = $xml->createElement('EncryptionVersion');
        $xmlEncryptionVersion->nodeValue = $this->context->getKeyring()->getUserSignatureEVersion();
        $xmlEncryptionCertificateInfo->appendChild($xmlEncryptionVersion);

        // Add PartnerID to HIARequestOrderData.
        $this->orderDataHandler->handlePartnerId($xmlH3KRequestOrderData, $xml);

        // Add UserID to HIARequestOrderData.
        $this->orderDataHandler->handleUserId($xmlH3KRequestOrderData, $xml);

        return $xml;
    }
}
