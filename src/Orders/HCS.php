<?php

namespace EbicsApi\Ebics\Orders;

use EbicsApi\Ebics\Builders\Request\BodyBuilder;
use EbicsApi\Ebics\Builders\Request\DataEncryptionInfoBuilder;
use EbicsApi\Ebics\Builders\Request\DataTransferBuilder;
use EbicsApi\Ebics\Builders\Request\HeaderBuilder;
use EbicsApi\Ebics\Builders\Request\MutableBuilder;
use EbicsApi\Ebics\Builders\Request\OrderDetailsBuilder;
use EbicsApi\Ebics\Builders\Request\RootBuilder;
use EbicsApi\Ebics\Builders\Request\StaticBuilder;
use EbicsApi\Ebics\Contexts\RequestContext;
use EbicsApi\Ebics\Models\Customer;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Keyring;
use EbicsApi\Ebics\Models\Order\UploadOrder;
use EbicsApi\Ebics\Models\Order\UploadOrderResult;
use EbicsApi\Ebics\Models\UserSignature;

/**
 * Upload for renewing user certificates.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Guillaume Sainthillier, Andrew Svirin
 */
final class HCS extends UploadOrder
{
    private Keyring $newKeyring;

    public function __construct(Keyring $newKeyring, ?RequestContext $context = null)
    {
        $this->newKeyring = $newKeyring;
        $this->context = $context;
    }

    public function prepareContext(): void
    {
        parent::prepareContext();
        $this->orderData = $this->createOrderData();
    }

    public function createRequest(): Request
    {
        return $this->buildRequest();
    }

    public function afterExecute(UploadOrderResult $orderResult): void
    {
        $signatureA = $this->newKeyring->getUserSignatureA();
        $signatureE = $this->newKeyring->getUserSignatureE();
        $signatureX = $this->newKeyring->getUserSignatureX();

        $this->context->getKeyring()->setUserSignatureA($signatureA);
        $this->context->getKeyring()->setUserSignatureE($signatureE);
        $this->context->getKeyring()->setUserSignatureX($signatureX);
    }

    private function buildRequest(): Request
    {
        $signatureData = new UserSignature();
        $this->userSignatureHandler->handle($signatureData, $this->transaction->getDigest());

        $signatureVersion = $this->context->getKeyring()->getUserSignatureAVersion();
        $dataDigest = $this->orderDataHandler->hash($this->orderData->getContent());

        $this->context
            ->setOrderType('HCS')
            ->setWithES(true)
            ->setTransactionKey($this->transaction->getKey())
            ->setNumSegments($this->transaction->getNumSegments())
            ->setSignatureData($signatureData)
            ->setSignatureVersion($signatureVersion)
            ->setDataDigest($dataDigest);

        return $this->requestFactory
            ->createRequestBuilderInstance()
            ->addContainerSecured(function (RootBuilder $builder) {
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
                                $this->requestFactory
                                    ->addOrderType(
                                        $orderDetailsBuilder,
                                        $this->context->getOrderType(),
                                        $this->context->isWithES() ?
                                            OrderDetailsBuilder::ORDER_ATTRIBUTE_OZHNN :
                                            OrderDetailsBuilder::ORDER_ATTRIBUTE_DZHNN
                                    )
                                    ->addStandardOrderParams();
                            })
                            ->addBankPubKeyDigests(
                                $this->context->getKeyring()->getBankSignatureXVersion(),
                                $this->requestFactory->signDigest($this->context->getKeyring()->getBankSignatureX()),
                                $this->context->getKeyring()->getBankSignatureEVersion(),
                                $this->requestFactory->signDigest($this->context->getKeyring()->getBankSignatureE())
                            )
                            ->addSecurityMedium(StaticBuilder::SECURITY_MEDIUM_0000)
                            ->addNumSegments($this->context->getNumSegments());
                    })->addMutable(function (MutableBuilder $builder) {
                        $builder->addTransactionPhase(MutableBuilder::PHASE_INITIALIZATION);
                    });
                })->addBody(function (BodyBuilder $builder) {
                    $builder->addDataTransfer(function (DataTransferBuilder $builder) {
                        $builder
                            ->addDataEncryptionInfo(function (DataEncryptionInfoBuilder $builder) {
                                $builder
                                    ->addEncryptionPubKeyDigest($this->context->getKeyring())
                                    ->addTransactionKey(
                                        $this->context->getTransactionKey(),
                                        $this->context->getKeyring()
                                    );
                            })
                            ->addSignatureData($this->context->getSignatureData(), $this->context->getTransactionKey())
                            ->addDataDigest($this->context->getSignatureVersion(), $this->context->getDataDigest());
                    });
                });
            })
            ->popInstance();
    }

    public function createOrderData(): Customer
    {
        $xml = new Customer();

        // Add HCSRequestOrderData to root.
        $xmlHCSRequestOrderData = $xml->createElementNS(
            $this->orderDataHandler->getH00XNamespace(),
            'HCSRequestOrderData'
        );
        $xmlHCSRequestOrderData->setAttributeNS(
            'http://www.w3.org/2000/xmlns/',
            'xmlns:esig',
            'http://www.ebics.org/' . $this->orderDataHandler->getS00XVersion()
        );
        $xmlHCSRequestOrderData->setAttributeNS(
            'http://www.w3.org/2000/xmlns/',
            'xmlns:ds',
            'http://www.w3.org/2000/09/xmldsig#'
        );
        $xml->appendChild($xmlHCSRequestOrderData);


        // Add AuthenticationPubKeyInfo to HCSRequestOrderData.
        $xmlAuthenticationPubKeyInfo = $xml->createElement('AuthenticationPubKeyInfo');
        $xmlHCSRequestOrderData->appendChild($xmlAuthenticationPubKeyInfo);

        if ($this->newKeyring->isCertified()) {
            $this->orderDataHandler->handleX509Data(
                $xmlAuthenticationPubKeyInfo,
                $xml,
                $this->newKeyring->getUserSignatureX()
            );
        }

        $this->orderDataHandler->handleAuthenticationPubKey(
            $xmlAuthenticationPubKeyInfo,
            $xml,
            $this->newKeyring->getUserSignatureX(),
            $this->context->getDateTime()
        );

        // Add AuthenticationVersion to AuthenticationPubKeyInfo.
        $xmlAuthenticationVersion = $xml->createElement('AuthenticationVersion');
        $xmlAuthenticationVersion->nodeValue = $this->newKeyring->getUserSignatureXVersion();
        $xmlAuthenticationPubKeyInfo->appendChild($xmlAuthenticationVersion);


        // Add EncryptionPubKeyInfo to HCSRequestOrderData.
        $xmlEncryptionPubKeyInfo = $xml->createElement('EncryptionPubKeyInfo');
        $xmlHCSRequestOrderData->appendChild($xmlEncryptionPubKeyInfo);

        if ($this->newKeyring->isCertified()) {
            $this->orderDataHandler->handleX509Data(
                $xmlEncryptionPubKeyInfo,
                $xml,
                $this->newKeyring->getUserSignatureE()
            );
        }

        $this->orderDataHandler->handleEncryptionPubKey(
            $xmlEncryptionPubKeyInfo,
            $xml,
            $this->newKeyring->getUserSignatureE(),
            $this->context->getDateTime()
        );

        // Add EncryptionVersion to EncryptionPubKeyInfo.
        $xmlEncryptionVersion = $xml->createElement('EncryptionVersion');
        $xmlEncryptionVersion->nodeValue = $this->newKeyring->getUserSignatureEVersion();
        $xmlEncryptionPubKeyInfo->appendChild($xmlEncryptionVersion);


        // Add SignaturePubKeyInfo to SignaturePubKeyOrderData.
        $xmlSignaturePubKeyInfo = $xml->createElement('esig:SignaturePubKeyInfo');
        $xmlHCSRequestOrderData->appendChild($xmlSignaturePubKeyInfo);

        if ($this->newKeyring->isCertified()) {
            $this->orderDataHandler->handleX509Data(
                $xmlSignaturePubKeyInfo,
                $xml,
                $this->newKeyring->getUserSignatureA()
            );
        }

        $this->orderDataHandler->handleSignaturePubKey(
            $xmlSignaturePubKeyInfo,
            $xml,
            $this->newKeyring->getUserSignatureA(),
            $this->context->getDateTime(),
            'esig'
        );

        // Add SignatureVersion to SignaturePubKeyInfo.
        $xmlSignatureVersion = $xml->createElement('esig:SignatureVersion');
        $xmlSignatureVersion->nodeValue = $this->newKeyring->getUserSignatureAVersion();
        $xmlSignaturePubKeyInfo->appendChild($xmlSignatureVersion);

        // Add PartnerID to HCSRequestOrderData.
        $this->orderDataHandler->handlePartnerId($xmlHCSRequestOrderData, $xml);

        // Add UserID to HCSRequestOrderData.
        $this->orderDataHandler->handleUserId($xmlHCSRequestOrderData, $xml);

        return $xml;
    }
}
