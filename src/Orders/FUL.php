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
use EbicsApi\Ebics\Contexts\FULContext;
use EbicsApi\Ebics\Contexts\RequestContext;
use EbicsApi\Ebics\Contracts\OrderDataInterface;
use EbicsApi\Ebics\Exceptions\MethodNotImplemented;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Keyring;
use EbicsApi\Ebics\Models\Order\UploadOrder;
use EbicsApi\Ebics\Models\UserSignature;

/**
 * EBICS FUL (File Upload) Order - Upload files to the bank.
 *
 * EBICS Protocol Context:
 * The FUL order is used to upload generic files to the bank, such as SEPA payment
 * orders, Direct Debit files, or other financial transaction data. It provides
 * a transparent transfer mechanism for files of any format.
 *
 * Protocol Details:
 * - Order Type: FUL
 * - Order Attribute: DZHNN (with authentication) or OZHNN (with electronic signature)
 * - Order Data Format: Arbitrary file data (automatically compressed and encrypted)
 * - Transaction Type: Upload order (multi-phase: initialization → transfer → receipt)
 *
 * Upload Process:
 * 1. Initialization Phase:
 *    - Create FUL order with file format and parameters
 *    - Send request with order metadata (numSegments, digest)
 *    - Receive transaction key from bank
 *
 * 2. Transfer Phase:
 *    - Split file into segments (CHUNK_SIZE = typically 1MB)
 *    - Encrypt each segment with transaction key
 *    - Upload segments sequentially
 *    - Bank acknowledges each segment
 *
 * 3. Receipt Phase:
 *    - Bank confirms receipt of all segments
 *    - Returns transaction status code
 *
 * Order Parameters:
 * - FileFormat: Specifies the file format (e.g., 'pain.001', 'pain.008')
 * - CountryCode: Country-specific format variant
 * - Parameters: Additional order-specific parameters
 *
 * Security Features:
 * - User signature (A005/A006) signs the order digest
 * - Transaction key encrypts the order data
 * - Bank signatures verify the response
 *
 * Typical Usage:
 * - Upload SEPA Credit Transfer (pain.001) files
 * - Upload SEPA Direct Debit (pain.008) files
 * - Upload other payment orders to the bank
 *
 * Supported Versions: 2.4, 2.5 (3.0 not yet implemented)
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class FUL extends UploadOrder
{
    private FULContext $fulContext;

    public function __construct(
        FULContext $fulContext,
        OrderDataInterface $orderData,
        ?RequestContext $context = null
    ) {
        $this->fulContext = $fulContext;
        $this->orderData = $orderData;
        $this->context = $context;
    }

    public function prepareContext(): void
    {
        parent::prepareContext();
        if (null === $this->fulContext->getCountryCode()) {
            $this->fulContext->setCountryCode($this->context->getBank()->getCountryCode());
        }
    }

    public function createRequest(): Request
    {
        if ($this->getVersion() === Keyring::VERSION_30) {
            throw new MethodNotImplemented('3.0');
        }

        return $this->buildRequest();
    }

    private function buildRequest(): Request
    {
        $signatureData = new UserSignature();
        $this->userSignatureHandler->handle($signatureData, $this->transaction->getDigest());

        $this->context
            ->setOrderType('FUL')
            ->setTransactionKey($this->transaction->getKey())
            ->setNumSegments($this->transaction->getNumSegments())
            ->setSignatureData($signatureData);

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
                                $this->addFULOrderParams($orderDetailsBuilder);
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
                            ->addSignatureData($this->context->getSignatureData(), $this->context->getTransactionKey());
                    });
                });
            })
            ->popInstance();
    }

    private function addFULOrderParams(OrderDetailsBuilder $orderDetailsBuilder): void
    {
        $xmlFULOrderParams = $orderDetailsBuilder->appendEmptyElementTo(
            'FULOrderParams',
            $orderDetailsBuilder->getInstance()
        );

        $orderDetailsBuilder->addParameters($xmlFULOrderParams, $this->fulContext->getParameters());

        $orderDetailsBuilder->appendElementTo('FileFormat', $this->fulContext->getFileFormat(), $xmlFULOrderParams, [
            'CountryCode' => $this->fulContext->getCountryCode(),
        ]);
    }
}
