<?php

namespace EbicsApi\Ebics\Orders;

use DateTimeInterface;
use EbicsApi\Ebics\Builders\Request\HeaderBuilder;
use EbicsApi\Ebics\Builders\Request\MutableBuilder;
use EbicsApi\Ebics\Builders\Request\OrderDetailsBuilder;
use EbicsApi\Ebics\Builders\Request\RootBuilder;
use EbicsApi\Ebics\Builders\Request\StaticBuilder;
use EbicsApi\Ebics\Contexts\BTDContext;
use EbicsApi\Ebics\Contexts\RequestContext;
use EbicsApi\Ebics\Exceptions\MethodNotImplemented;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Keyring;
use EbicsApi\Ebics\Models\Order\DownloadOrder;

/**
 * Download request files of any BTF structure.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class BTD extends DownloadOrder
{
    private BTDContext $btdContext;

    private ?DateTimeInterface $startDateTime;

    private ?DateTimeInterface $endDateTime;

    public function __construct(
        BTDContext $btdContext,
        ?DateTimeInterface $startDateTime = null,
        ?DateTimeInterface $endDateTime = null,
        ?RequestContext $context = null
    ) {
        $this->btdContext = $btdContext;
        $this->startDateTime = $startDateTime;
        $this->endDateTime = $endDateTime;
        $this->context = $context;
    }

    public function prepareContext(): void
    {
        parent::prepareContext();
        $this->context
            ->setStartDateTime($this->startDateTime)
            ->setEndDateTime($this->endDateTime);
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

    public function getParserFormat(): string
    {
        return $this->btdContext->getParserFormat();
    }

    private function buildRequest(): Request
    {
        $this->context
            ->setOrderType('BTD');

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
                                $this->addBTDOrderParams(
                                    $orderDetailsBuilder,
                                    $this->context->getStartDateTime(),
                                    $this->context->getEndDateTime()
                                );
                            })
                            ->addBankPubKeyDigests(
                                $this->context->getKeyring()->getBankSignatureXVersion(),
                                $this->requestFactory->signDigest($this->context->getKeyring()->getBankSignatureX()),
                                $this->context->getKeyring()->getBankSignatureEVersion(),
                                $this->requestFactory->signDigest($this->context->getKeyring()->getBankSignatureE())
                            )
                            ->addSecurityMedium(StaticBuilder::SECURITY_MEDIUM_0000);
                    })->addMutable(function (MutableBuilder $builder) {
                        $builder
                            ->addTransactionPhase(MutableBuilder::PHASE_INITIALIZATION);
                    });
                })->addBody();
            })
            ->popInstance();
    }

    private function addBTDOrderParams(
        OrderDetailsBuilder $orderDetailsBuilder,
        ?DateTimeInterface $startDateTime = null,
        ?DateTimeInterface $endDateTime = null
    ): void {
        $xmlBTDOrderParams = $orderDetailsBuilder->appendEmptyElementTo(
            'BTDOrderParams',
            $orderDetailsBuilder->getInstance()
        );

        $xmlService = $orderDetailsBuilder->appendEmptyElementTo('Service', $xmlBTDOrderParams);

        $orderDetailsBuilder->appendElementTo('ServiceName', $this->btdContext->getServiceName(), $xmlService);

        if (null !== $this->btdContext->getScope()) {
            $orderDetailsBuilder->appendElementTo(
                'Scope',
                $this->btdContext->getScope(),
                $xmlService
            );
        }

        if (null !== $this->btdContext->getServiceOption()) {
            $orderDetailsBuilder->appendElementTo('ServiceOption', $this->btdContext->getServiceOption(), $xmlService);
        }

        if (null !== $this->btdContext->getContainerType()) {
            $orderDetailsBuilder->appendEmptyElementTo('Container', $xmlService, [
                'containerType' => $this->btdContext->getContainerType(),
            ]);
        }

        $xmlMsgName = $orderDetailsBuilder->appendElementTo('MsgName', $this->btdContext->getMsgName(), $xmlService);

        if (null !== $this->btdContext->getMsgNameVersion()) {
            $xmlMsgName->setAttribute('version', $this->btdContext->getMsgNameVersion());
        }

        if (null !== $this->btdContext->getMsgNameVariant()) {
            $xmlMsgName->setAttribute('variant', $this->btdContext->getMsgNameVariant());
        }

        if (null !== $this->btdContext->getMsgNameFormat()) {
            $xmlMsgName->setAttribute('format', $this->btdContext->getMsgNameFormat());
        }

        if (null !== $startDateTime && null !== $endDateTime) {
            $xmlDateRange = $orderDetailsBuilder->createDateRange(
                $startDateTime,
                $endDateTime
            );
            $xmlBTDOrderParams->appendChild($xmlDateRange);
        }

        $orderDetailsBuilder->addParameters($xmlBTDOrderParams, $this->btdContext->getParameters());
    }
}
