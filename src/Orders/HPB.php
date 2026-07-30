<?php

namespace EbicsApi\Ebics\Orders;

use EbicsApi\Ebics\Builders\Request\HeaderBuilder;
use EbicsApi\Ebics\Builders\Request\OrderDetailsBuilder;
use EbicsApi\Ebics\Builders\Request\RootBuilder;
use EbicsApi\Ebics\Builders\Request\StaticBuilder;
use EbicsApi\Ebics\Contexts\RequestContext;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Order\InitializationOrder;
use EbicsApi\Ebics\Models\Order\InitializationOrderResult;

/**
 * EBICS HPB (Handshake Public Bank) Order - Download bank's public signatures.
 *
 * EBICS Protocol Context:
 * The HPB order retrieves the bank's authentication (X002) and encryption (E002)
 * public keys. This is the final step in the initial key exchange process,
 * allowing the client to verify bank responses and encrypt data for the bank.
 *
 * Protocol Details:
 * - Order Type: HPB
 * - Order Attribute: DZHNN (with authentication) or OZHNN (with electronic signature)
 * - Order Data Format: None (request only, response contains bank signatures)
 * - Transaction Type: Initialization order (single request-response)
 *
 * Bank Signature X (X002) Purpose:
 * - Verifies the bank's authentication signature in responses
 * - Ensures responses genuinely come from the expected bank
 * - Required for verifying EBICS response integrity
 *
 * Bank Signature E (E002) Purpose:
 * - Encrypts data sent to the bank
 * - Bank's public key for asymmetric encryption
 * - Used to encrypt transaction keys during uploads
 *
 * HPB Response Structure:
 * - AuthenticationPubKeyInfo: Bank's X002 public key and certificate
 * - AuthenticationVersion: Bank's X002 version identifier
 * - EncryptionPubKeyInfo: Bank's E002 public key and certificate
 * - EncryptionVersion: Bank's E002 version identifier
 *
 * Typical Usage:
 * 1. Complete INI and HIA orders to send client's public keys
 * 2. Execute HPB order to retrieve bank's public keys
 * 3. Store bank signatures in keyring for all future transactions
 *
 * Execution Sequence:
 * INI → HIA → HPB  (for versions 2.4/2.5)
 * or
 * H3K → HPB  (for version 3.0)
 *
 * Security Note:
 * The HPB order should be executed only once during initial setup.
 * The bank's public keys are then stored and used for all subsequent
 * transactions. If keys are lost, the initialization process must
 * be repeated.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class HPB extends InitializationOrder
{
    public function __construct(?RequestContext $context = null)
    {
        $this->context = $context;
    }

    public function createRequest(): Request
    {
        return $this->buildRequest();
    }

    public function afterExecute(InitializationOrderResult $orderResult): void
    {
        $signatureX = $this->orderDataHandler->retrieveAuthenticationSignature($orderResult->getDocument());
        $signatureE = $this->orderDataHandler->retrieveEncryptionSignature($orderResult->getDocument());
        $this->context->getKeyring()->setBankSignatureX($signatureX);
        $this->context->getKeyring()->setBankSignatureE($signatureE);
    }

    private function buildRequest(): Request
    {
        $this->context
            ->setOrderType('HPB');

        return $this->requestFactory
            ->createRequestBuilderInstance()
            ->addContainerSecuredNoPubKeyDigests(function (RootBuilder $builder) {
                $builder->addHeader(function (HeaderBuilder $builder) {
                    $builder->addStatic(function (StaticBuilder $builder) {
                        $builder
                            ->addHostId($this->context->getBank()->getHostId())
                            ->addRandomNonce()
                            ->addTimestamp($this->context->getDateTime())
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
                })->addBody();
            })
            ->popInstance();
    }
}
