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
use EbicsApi\Ebics\Models\GenericOrderData;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Order\StandardOrder;
use EbicsApi\Ebics\Models\Order\StandardOrderResult;

/**
 * EBICS HIA (Handshake Initialization Authentication) Order.
 *
 * EBICS Protocol Context:
 * The HIA order transmits the user's encryption (E002) and authentication (X002)
 * public keys to the bank. This completes the key exchange process started with
 * the INI order, establishing all three required signature types.
 *
 * Protocol Details:
 * - Order Type: HIA
 * - Order Attribute: DZNNN (no authentication, no encryption needed)
 * - Order Data Format: HIARequestOrderData (XML with AuthenticationPubKeyInfo and EncryptionPubKeyInfo)
 * - Transaction Type: Standard order (single request-response)
 *
 * Signature E (E002) Purpose:
 * - Used to encrypt order data during transmission
 * - Ensures confidentiality of sensitive financial data
 * - Bank uses this public key to encrypt responses to the client
 *
 * Signature X (X002) Purpose:
 * - Used to authenticate the client to the EBICS server
 * - Signs every request to prove client identity
 * - Required for all EBICS orders
 *
 * HIA Request Structure:
 * - AuthenticationPubKeyInfo: X002 public key and certificate
 * - AuthenticationVersion: X002 version identifier
 * - EncryptionPubKeyInfo: E002 public key and certificate
 * - EncryptionVersion: E002 version identifier
 * - PartnerID and UserID: User identification
 *
 * Typical Usage:
 * 1. Generate signatures E and X via createUserSignatures()
 * 2. Execute HIA order after INI order (or standalone for version 3.0)
 * 3. Bank stores both public keys for secure communication
 *
 * Execution Sequence:
 * INI → HIA → HPB  (for versions 2.4/2.5)
 * or
 * H3K → HPB  (for version 3.0, where H3K combines INI+HIA)
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class HIA extends StandardOrder
{
    private SignatureInterface $signatureE;
    private SignatureInterface $signatureX;

    public function __construct(?RequestContext $context = null)
    {
        $this->context = $context;
    }

    public function createRequest(): Request
    {
        $this->signatureE = $this->context->getKeyring()->getUserSignatureE();
        $this->signatureX = $this->context->getKeyring()->getUserSignatureX();

        return $this->buildRequest();
    }

    public function afterExecute(StandardOrderResult $orderResult): void
    {
        $this->context->getKeyring()->setUserSignatureE($this->signatureE);
        $this->context->getKeyring()->setUserSignatureX($this->signatureX);
    }

    private function buildRequest(): Request
    {
        $orderData = $this->createOrderData();

        $this->context
            ->setOrderType('HIA')
            ->setOrderData($orderData->getContent());

        return $this->requestFactory
            ->createRequestBuilderInstance()
            ->addContainerUnsecured(function (RootBuilder $builder) {
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
                                    OrderDetailsBuilder::ORDER_ATTRIBUTE_DZNNN
                                );
                            })
                            ->addSecurityMedium(StaticBuilder::SECURITY_MEDIUM_0000);
                    })->addMutable();
                })->addBody(function (BodyBuilder $builder) {
                    $builder->addDataTransfer(function (DataTransferBuilder $builder) {
                        $builder->addOrderData($this->context->getOrderData());
                    });
                });
            })
            ->popInstance();
    }

    private function createOrderData(): GenericOrderData
    {
        $xml = new GenericOrderData();

        // Add HIARequestOrderData to root.
        $xmlHIARequestOrderData = $xml->createElementNS(
            $this->orderDataHandler->getH00XNamespace(),
            'HIARequestOrderData'
        );
        $xmlHIARequestOrderData->setAttributeNS(
            'http://www.w3.org/2000/xmlns/',
            'xmlns:ds',
            'http://www.w3.org/2000/09/xmldsig#'
        );

        $xml->appendChild($xmlHIARequestOrderData);

        // Add AuthenticationPubKeyInfo to HIARequestOrderData.
        $xmlAuthenticationPubKeyInfo = $xml->createElement('AuthenticationPubKeyInfo');
        $xmlHIARequestOrderData->appendChild($xmlAuthenticationPubKeyInfo);

        if ($this->context->getKeyring()->isCertified()) {
            $this->orderDataHandler->handleX509Data($xmlAuthenticationPubKeyInfo, $xml, $this->signatureX);
        }

        $this->orderDataHandler->handleAuthenticationPubKey(
            $xmlAuthenticationPubKeyInfo,
            $xml,
            $this->signatureX,
            $this->context->getDateTime()
        );

        // Add AuthenticationVersion to AuthenticationPubKeyInfo.
        $xmlAuthenticationVersion = $xml->createElement('AuthenticationVersion');
        $xmlAuthenticationVersion->nodeValue = $this->context->getKeyring()->getUserSignatureXVersion();
        $xmlAuthenticationPubKeyInfo->appendChild($xmlAuthenticationVersion);

        // Add EncryptionPubKeyInfo to HIARequestOrderData.
        $xmlEncryptionPubKeyInfo = $xml->createElement('EncryptionPubKeyInfo');
        $xmlHIARequestOrderData->appendChild($xmlEncryptionPubKeyInfo);

        if ($this->context->getKeyring()->isCertified()) {
            $this->orderDataHandler->handleX509Data($xmlEncryptionPubKeyInfo, $xml, $this->signatureE);
        }

        $this->orderDataHandler->handleEncryptionPubKey(
            $xmlEncryptionPubKeyInfo,
            $xml,
            $this->signatureE,
            $this->context->getDateTime()
        );

        // Add EncryptionVersion to EncryptionPubKeyInfo.
        $xmlEncryptionVersion = $xml->createElement('EncryptionVersion');
        $xmlEncryptionVersion->nodeValue = $this->context->getKeyring()->getUserSignatureEVersion();
        $xmlEncryptionPubKeyInfo->appendChild($xmlEncryptionVersion);

        // Add PartnerID to HIARequestOrderData.
        $this->orderDataHandler->handlePartnerId($xmlHIARequestOrderData, $xml);

        // Add UserID to HIARequestOrderData.
        $this->orderDataHandler->handleUserId($xmlHIARequestOrderData, $xml);

        return $xml;
    }
}
