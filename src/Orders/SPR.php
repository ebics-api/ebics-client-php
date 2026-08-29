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
use EbicsApi\Ebics\Models\EmptyOrderData;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Order\UploadOrder;
use EbicsApi\Ebics\Models\UserSignature;

/**
 * Suspend activated Keyring.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class SPR extends UploadOrder
{
    public function __construct(?RequestContext $context = null)
    {
        $this->context = $context;
    }

    public function prepareContext(): void
    {
        parent::prepareContext();
        $this->orderData = new EmptyOrderData();
    }

    public function createRequest(): Request
    {
        return $this->buildRequest();
    }

    private function buildRequest(): Request
    {
        $signatureData = new UserSignature();
        $this->userSignatureHandler->handle($signatureData, $this->transaction->getDigest());

        $signatureVersion = $this->context->getKeyring()->getUserSignatureAVersion();
        $dataDigest = $this->orderDataHandler->hash($this->orderData->getTrimmedContent());

        $this->context
            ->setOrderType('SPR')
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
                                        OrderDetailsBuilder::ORDER_ATTRIBUTE_UZHNN
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
}
