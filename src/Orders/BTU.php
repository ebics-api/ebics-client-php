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
use EbicsApi\Ebics\Contexts\BTUContext;
use EbicsApi\Ebics\Contexts\RequestContext;
use EbicsApi\Ebics\Contracts\OrderDataInterface;
use EbicsApi\Ebics\Exceptions\MethodNotImplemented;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Keyring;
use EbicsApi\Ebics\Models\Order\UploadOrder;
use EbicsApi\Ebics\Models\UserSignature;

/**
 * Upload the files to the bank of any BTF structure.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class BTU extends UploadOrder
{
    private BTUContext $btuContext;

    public function __construct(
        BTUContext $btuContext,
        OrderDataInterface $orderData,
        ?RequestContext $context = null
    ) {
        $this->btuContext = $btuContext;
        $this->orderData = $orderData;
        $this->context = $context;
    }

    public function createRequest(): Request
    {
        if ($this->getVersion() === Keyring::VERSION_24) {
            throw new MethodNotImplemented('2.4');
        }

        if ($this->getVersion() === Keyring::VERSION_25) {
            throw new MethodNotImplemented('2.5');
        }

        return $this->buildRequest();
    }

    private function buildRequest(): Request
    {
        $signatureData = new UserSignature();

        $this->userSignatureHandler->handle($signatureData, $this->transaction->getDigest());

        $signatureVersion = $this->context->getKeyring()->getUserSignatureAVersion();
        $dataDigest = $this->orderDataHandler->hash($this->orderData->getContent());

        $this->context
            ->setOrderType('BTU')
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
                                    );
                                $this->addBTUOrderParams($orderDetailsBuilder);
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

    private function addBTUOrderParams(OrderDetailsBuilder $orderDetailsBuilder): void
    {
        $xmlBTUOrderParams = $orderDetailsBuilder->appendEmptyElementTo(
            'BTUOrderParams',
            $orderDetailsBuilder->getInstance(),
            [
                'fileName' => $this->btuContext->getFileName(),
            ]
        );

        $xmlService = $orderDetailsBuilder->appendEmptyElementTo('Service', $xmlBTUOrderParams);

        $orderDetailsBuilder->appendElementTo('ServiceName', $this->btuContext->getServiceName(), $xmlService);

        if (null !== $this->btuContext->getScope()) {
            $orderDetailsBuilder->appendElementTo('Scope', $this->btuContext->getScope(), $xmlService);
        }

        if (null !== $this->btuContext->getServiceOption()) {
            $orderDetailsBuilder->appendElementTo('ServiceOption', $this->btuContext->getServiceOption(), $xmlService);
        }

        $xmlMsgName = $orderDetailsBuilder->appendElementTo('MsgName', $this->btuContext->getMsgName(), $xmlService);

        if (null !== $this->btuContext->getMsgNameVersion()) {
            $xmlMsgName->setAttribute('version', $this->btuContext->getMsgNameVersion());
        }

        if (null !== $this->btuContext->getMsgNameVariant()) {
            $xmlMsgName->setAttribute('variant', $this->btuContext->getMsgNameVariant());
        }

        if (null !== $this->btuContext->getMsgNameFormat()) {
            $xmlMsgName->setAttribute('format', $this->btuContext->getMsgNameFormat());
        }

        if ($this->context->isWithES()) {
            $xmlSignatureFlag = $orderDetailsBuilder->appendEmptyElementTo('SignatureFlag', $xmlBTUOrderParams);

            $xmlSignatureFlag->setAttribute('requestEDS', 'true');
        }

        $orderDetailsBuilder->addParameters($xmlBTUOrderParams, $this->btuContext->getParameters());
    }
}
