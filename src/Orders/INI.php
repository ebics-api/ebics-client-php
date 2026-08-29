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
 * EBICS INI (Initialization) Order - Send signature A (A005/A006) to the bank.
 *
 * EBICS Protocol Context:
 * The INI order transmits the user's authorization signature (Signature A) public key
 * to the bank. This is part of the initial key exchange process required before
 * executing authorized orders.
 *
 * Protocol Details:
 * - Order Type: INI
 * - Order Attribute: DZNNN (no authentication, no encryption needed)
 * - Order Data Format: SignaturePubKeyOrderData (XML containing SignaturePubKeyInfo)
 * - Transaction Type: Standard order (single request-response)
 *
 * Signature A (A005/A006) Purpose:
 * - Used to sign order requests requiring user authorization
 * - Proves the user's authority to execute orders
 * - Required for upload orders (FUL, BTU) and certain download orders
 *
 * A005 vs A006:
 * - A005: Older signature format (RSA with SHA-1)
 * - A006: Newer signature format (RSA with SHA-256, recommended)
 *
 * Typical Usage:
 * 1. Generate signature A via createUserSignatures()
 * 2. Execute INI order to register with bank
 * 3. Bank stores the public key for future signature verification
 *
 * Execution Sequence:
 * INI → HIA → HPB  (for versions 2.4/2.5)
 * or
 * H3K → HPB  (for version 3.0, combined initialization)
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class INI extends StandardOrder
{
    private SignatureInterface $signatureA;

    public function __construct(?RequestContext $context = null)
    {
        $this->context = $context;
    }

    public function createRequest(): Request
    {
        $this->signatureA = $this->context->getKeyring()->getUserSignatureA();

        return $this->buildRequest();
    }

    public function afterExecute(StandardOrderResult $orderResult): void
    {
        $this->context->getKeyring()->setUserSignatureA($this->signatureA);
    }

    private function buildRequest(): Request
    {
        $orderData = $this->createOrderData();

        $this->context
            ->setOrderType('INI')
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

    public function createOrderData(): GenericOrderData
    {
        $xml = new GenericOrderData();

        // Add SignaturePubKeyOrderData to root.
        $xmlSignaturePubKeyOrderData =  $xml->createElementNS(
            'http://www.ebics.org/' . $this->orderDataHandler->getS00XVersion(),
            'SignaturePubKeyOrderData'
        );

        $xmlSignaturePubKeyOrderData->setAttributeNS(
            'http://www.w3.org/2000/xmlns/',
            'xmlns:ds',
            'http://www.w3.org/2000/09/xmldsig#'
        );
        $xml->appendChild($xmlSignaturePubKeyOrderData);

        // Add SignaturePubKeyInfo to SignaturePubKeyOrderData.
        $xmlSignaturePubKeyInfo = $xml->createElement('SignaturePubKeyInfo');
        $xmlSignaturePubKeyOrderData->appendChild($xmlSignaturePubKeyInfo);

        if ($this->context->getKeyring()->isCertified()) {
            $this->orderDataHandler->handleX509Data($xmlSignaturePubKeyInfo, $xml, $this->signatureA);
        }

        $this->orderDataHandler->handleSignaturePubKey(
            $xmlSignaturePubKeyInfo,
            $xml,
            $this->signatureA,
            $this->context->getDateTime()
        );

        // Add SignatureVersion to SignaturePubKeyInfo.
        $xmlSignatureVersion = $xml->createElement('SignatureVersion');
        $xmlSignatureVersion->nodeValue = $this->context->getKeyring()->getUserSignatureAVersion();
        $xmlSignaturePubKeyInfo->appendChild($xmlSignatureVersion);

        // Add PartnerID to SignaturePubKeyOrderData.
        $this->orderDataHandler->handlePartnerId($xmlSignaturePubKeyOrderData, $xml);

        // Add UserID to SignaturePubKeyOrderData.
        $this->orderDataHandler->handleUserId($xmlSignaturePubKeyOrderData, $xml);

        return $xml;
    }
}
