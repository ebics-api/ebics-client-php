<?php

namespace EbicsApi\Ebics\Orders;

use DateTimeInterface;
use EbicsApi\Ebics\Builders\Request\HeaderBuilder;
use EbicsApi\Ebics\Builders\Request\MutableBuilder;
use EbicsApi\Ebics\Builders\Request\OrderDetailsBuilder;
use EbicsApi\Ebics\Builders\Request\RootBuilder;
use EbicsApi\Ebics\Builders\Request\StaticBuilder;
use EbicsApi\Ebics\Contexts\RequestContext;
use EbicsApi\Ebics\Contracts\EbicsClientInterface;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Order\DownloadOrder;

/**
 * Download transaction status (XML).
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class HAC extends DownloadOrder
{
    private ?DateTimeInterface $startDateTime;

    private ?DateTimeInterface $endDateTime;

    public function __construct(
        ?DateTimeInterface $startDateTime = null,
        ?DateTimeInterface $endDateTime = null,
        ?RequestContext $context = null
    ) {
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
        return $this->buildRequest();
    }

    public function getParserFormat(): string
    {
        return EbicsClientInterface::FILE_PARSER_FORMAT_TEXT;
    }

    private function buildRequest(): Request
    {
        $this->context
            ->setOrderType('HAC');

        return $this
            ->requestFactory->createRequestBuilderInstance()
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
                                    ->addStandardOrderParams(
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
}
