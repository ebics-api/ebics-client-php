<?php

namespace EbicsApi\Ebics;

use EbicsApi\Ebics\Contracts\EbicsClientInterface;
use EbicsApi\Ebics\Contracts\EbicsClientOptionsInterface;
use EbicsApi\Ebics\Contracts\HttpClientInterface;
use EbicsApi\Ebics\Contracts\LoggerInterface;
use EbicsApi\Ebics\Contracts\Order\DownloadOrderInterface;
use EbicsApi\Ebics\Contracts\Order\InitializationOrderInterface;
use EbicsApi\Ebics\Contracts\Order\StandardOrderInterface;
use EbicsApi\Ebics\Contracts\Order\UploadOrderInterface;
use EbicsApi\Ebics\Contracts\OrderDataInterface;
use EbicsApi\Ebics\Contracts\Processor\AESEncryptorInterface;
use EbicsApi\Ebics\Contracts\Processor\Base64EncoderInterface;
use EbicsApi\Ebics\Contracts\Processor\ZipCompressorInterface;
use EbicsApi\Ebics\Contracts\SignatureInterface;
use EbicsApi\Ebics\Exceptions\EbicsException;
use EbicsApi\Ebics\Exceptions\EbicsResponseException;
use EbicsApi\Ebics\Exceptions\PasswordEbicsException;
use EbicsApi\Ebics\Exceptions\SignatureEbicsException;
use EbicsApi\Ebics\Factories\CertificateX509Factory;
use EbicsApi\Ebics\Factories\Crypt\BigIntegerFactory;
use EbicsApi\Ebics\Factories\Crypt\RSAFactory;
use EbicsApi\Ebics\Factories\DocumentFactory;
use EbicsApi\Ebics\Factories\EbicsExceptionFactory;
use EbicsApi\Ebics\Factories\EbicsFactoryV24;
use EbicsApi\Ebics\Factories\EbicsFactoryV25;
use EbicsApi\Ebics\Factories\EbicsFactoryV30;
use EbicsApi\Ebics\Factories\OrderResultFactory;
use EbicsApi\Ebics\Factories\RequestFactory;
use EbicsApi\Ebics\Factories\SegmentFactory;
use EbicsApi\Ebics\Factories\SignatureFactory;
use EbicsApi\Ebics\Factories\TransactionFactory;
use EbicsApi\Ebics\Handlers\OrderDataHandler;
use EbicsApi\Ebics\Handlers\ResponseHandler;
use EbicsApi\Ebics\Handlers\UserSignatureHandler;
use EbicsApi\Ebics\Models\Bank;
use EbicsApi\Ebics\Models\Crypt\Key;
use EbicsApi\Ebics\Models\Crypt\KeyPair;
use EbicsApi\Ebics\Models\DownloadSegment;
use EbicsApi\Ebics\Models\DownloadTransaction;
use EbicsApi\Ebics\Models\EbicsClientOptions;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Http\Response;
use EbicsApi\Ebics\Models\InitializationSegment;
use EbicsApi\Ebics\Models\InitializationTransaction;
use EbicsApi\Ebics\Models\Keyring;
use EbicsApi\Ebics\Models\Order\DownloadOrderResult;
use EbicsApi\Ebics\Models\Order\InitializationOrderResult;
use EbicsApi\Ebics\Models\Order\StandardOrderResult;
use EbicsApi\Ebics\Models\Order\UploadOrderResult;
use EbicsApi\Ebics\Models\UploadTransaction;
use EbicsApi\Ebics\Models\User;
use EbicsApi\Ebics\Models\X509\ContentX509Generator;
use EbicsApi\Ebics\Services\ArrayLogger;
use EbicsApi\Ebics\Services\CryptService;
use EbicsApi\Ebics\Services\CurlHttpClient;
use EbicsApi\Ebics\Services\Processor\AESEncryptor;
use EbicsApi\Ebics\Services\Processor\Base64Encoder;
use EbicsApi\Ebics\Services\Processor\ZipCompressor;
use EbicsApi\Ebics\Services\RandomService;
use EbicsApi\Ebics\Services\SchemaValidator;
use EbicsApi\Ebics\Services\TransactionKeyResolver;
use EbicsApi\Ebics\Services\XmlService;
use EbicsApi\Ebics\Services\ZipArchiveExtractor;
use LogicException;

/**
 * EBICS client representation.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class EbicsClient implements EbicsClientInterface
{
    private readonly Bank $bank;
    private readonly User $user;
    private readonly Keyring $keyring;
    private readonly OrderDataHandler $orderDataHandler;
    private readonly UserSignatureHandler $userSignatureHandler;
    private readonly ResponseHandler $responseHandler;
    private readonly RequestFactory $requestFactory;
    private readonly CryptService $cryptService;
    private readonly ZipArchiveExtractor $zipArchiveExtractor;
    private readonly Base64EncoderInterface $base64Service;
    private readonly XmlService $xmlService;
    private readonly DocumentFactory $documentFactory;
    private readonly OrderResultFactory $orderResultFactory;
    private readonly SignatureFactory $signatureFactory;
    private readonly HttpClientInterface $httpClient;
    private readonly TransactionFactory $transactionFactory;
    private readonly SegmentFactory $segmentFactory;
    private readonly RSAFactory $rsaFactory;
    private readonly SchemaValidator $schemaValidator;
    private readonly LoggerInterface $logger;
    private readonly Base64EncoderInterface $base64Encoder;
    private readonly AESEncryptorInterface $aesEncryptor;
    private readonly ZipCompressorInterface $zipCompressor;
    private readonly TransactionKeyResolver $transactionKeyResolver;

    /**
     * Constructor.
     *
     * @param Bank $bank
     * @param User $user
     * @param Keyring $keyring
     * @param EbicsClientOptionsInterface|null $options
     */
    public function __construct(Bank $bank, User $user, Keyring $keyring, ?EbicsClientOptionsInterface $options = null)
    {
        $this->bank = $bank;
        $this->user = $user;
        $this->keyring = $keyring;

        if (Keyring::VERSION_24 === $keyring->getVersion()) {
            $ebicsFactory = new EbicsFactoryV24();
        } elseif (Keyring::VERSION_25 === $keyring->getVersion()) {
            $ebicsFactory = new EbicsFactoryV25();
        } elseif (Keyring::VERSION_30 === $keyring->getVersion()) {
            $ebicsFactory = new EbicsFactoryV30();
        } else {
            throw new LogicException(sprintf('Version "%s" is not implemented', $keyring->getVersion()));
        }

        if (null === $options) {
            $options = new EbicsClientOptions();
        }

        $this->transactionKeyResolver = new TransactionKeyResolver();
        $this->aesEncryptor = $options->getAesEncryptor() ?? new AESEncryptor($this->transactionKeyResolver);
        $this->rsaFactory = new RSAFactory($this->aesEncryptor, $options->getRsaClassMap());
        $this->segmentFactory = new SegmentFactory();
        $this->base64Service = $options->getBase64Encoder() ?? new Base64Encoder();
        $this->cryptService = new CryptService(
            $this->rsaFactory,
            $this->aesEncryptor,
            new RandomService(),
            $this->base64Service
        );
        $this->zipArchiveExtractor = new ZipArchiveExtractor();
        $this->zipCompressor = $options->getZipCompressor() ?? new ZipCompressor();
        $this->signatureFactory = new SignatureFactory($this->rsaFactory);

        $this->orderDataHandler = $ebicsFactory->createOrderDataHandler(
            $this->base64Service,
            $user,
            $keyring,
            $this->cryptService,
            $this->signatureFactory,
            new CertificateX509Factory(),
            new BigIntegerFactory()
        );

        $this->schemaValidator = new SchemaValidator($options->getSchemaDir());

        $this->userSignatureHandler = $ebicsFactory->createUserSignatureHandler(
            $this->base64Service,
            $user,
            $keyring,
            $this->cryptService,
            $this->schemaValidator
        );

        $this->requestFactory = $ebicsFactory->createRequestFactory(
            $bank,
            $user,
            $keyring,
            $this->userSignatureHandler,
            $this->orderDataHandler,
            $ebicsFactory->createDigestResolver($this->cryptService),
            $ebicsFactory->createRequestBuilder(
                $keyring,
                $this->cryptService,
                $this->base64Service,
                $this->schemaValidator
            ),
            $this->cryptService,
            $this->zipCompressor,
            $this->base64Service
        );

        $this->responseHandler = $ebicsFactory->createResponseHandler(
            $this->segmentFactory,
            $this->cryptService,
            $this->zipCompressor,
            $this->base64Service
        );

        $this->xmlService = new XmlService();
        $this->documentFactory = new DocumentFactory();
        $this->orderResultFactory = new OrderResultFactory();
        $this->transactionFactory = new TransactionFactory();
        $this->httpClient = $options->getHttpClient() ?? new CurlHttpClient(
            $options->getCurlOptions()
        );
        $this->logger = $options->getLogger() ?? new ArrayLogger();
        $this->base64Encoder = $this->base64Service;
    }

    /**
     * @inheritDoc
     *
     * The process involves:
     * 1. Preparing the order context with bank and user identification
     * 2. Creating the XML request with appropriate signatures
     * 3. Initializing a transaction with the bank
     * 4. Processing the bank's response and storing cryptographic material
     *
     * @throws EbicsException If request creation or transaction initialization fails
     * @throws EbicsResponseException If the bank returns an error response
     */
    public function executeInitializationOrder(InitializationOrderInterface $order): InitializationOrderResult
    {
        $order->useRequestFactory($this->requestFactory);
        $order->useOrderDataHandler($this->orderDataHandler);
        $order->useUserSignatureHandler($this->userSignatureHandler);
        $order->prepareContext();

        $orderType = $order->getOrderType();
        $this->logger->info('start_initialization_order', [
            'order_type' => $orderType,
            'host_id' => $this->bank->getHostId(),
            'partner_id' => $this->user->getPartnerId(),
            'user_id' => $this->user->getUserId(),
        ]);

        $transaction = $this->initializeTransaction(
            function () use ($order) {
                return $order->createRequest();
            },
            false
        );

        $this->logger->info('complete_initialization_order', [
            'order_type' => $orderType,
        ]);

        $result = $this->createInitializationOrderResult($transaction);
        $order->afterExecute($result);

        return $result;
    }

    /**
     * @inheritDoc
     *
     * The execution flow:
     * 1. Prepare the order context
     * 2. Create the XML request with user signature
     * 3. Send request to bank via HTTP POST
     * 4. Parse and validate the response
     * 5. Return the result with any retrieved data
     *
     * @throws EbicsException If request creation fails
     * @throws EbicsResponseException If the bank returns an error response
     */
    public function executeStandardOrder(StandardOrderInterface $order): StandardOrderResult
    {
        $order->useRequestFactory($this->requestFactory);
        $order->useOrderDataHandler($this->orderDataHandler);
        $order->useUserSignatureHandler($this->userSignatureHandler);
        $order->prepareContext();

        $orderType = $order->getOrderType();
        $this->logger->info('start_standard_order', [
            'order_type' => $orderType,
            'host_id' => $this->bank->getHostId(),
            'partner_id' => $this->user->getPartnerId(),
            'user_id' => $this->user->getUserId(),
        ]);

        $request = $order->createRequest();
        $response = $this->httpClient->post($this->bank->getUrl(), $request);
        $this->verifyResponseAuthSignature($response);
        $this->responseHandler->checkResponseReturnCode($request, $response);

        $this->logger->info('complete_standard_order', [
            'order_type' => $orderType,
        ]);

        $result = $this->createStandardOrderResult($response);
        $order->afterExecute($result);

        return $result;
    }

    /**
     * @inheritDoc
     *
     * The method automatically:
     * - Handles segmented downloads for large files
     * - Reassembles segments into complete data
     * - Decrypts the data using the transaction key
     * - Decompresses ZIP-encoded data
     * - Parses the result according to the specified format (text, XML, files)
     *
     * @throws EbicsException If request creation, download, or decryption fails
     * @throws EbicsResponseException If the bank returns an error response
     */
    public function executeDownloadOrder(DownloadOrderInterface $order): DownloadOrderResult
    {
        $order->useRequestFactory($this->requestFactory);
        $order->useOrderDataHandler($this->orderDataHandler);
        $order->useUserSignatureHandler($this->userSignatureHandler);
        $order->prepareContext();

        $orderType = $order->getOrderType();
        $this->logger->info('start_download_order', [
            'order_type' => $orderType,
            'host_id' => $this->bank->getHostId(),
            'partner_id' => $this->user->getPartnerId(),
            'user_id' => $this->user->getUserId(),
        ]);

        $transaction = $this->downloadTransaction(
            function () use ($order) {
                return $order->createRequest();
            },
            $order->getContext()->getAckClosure()
        );

        $this->logger->info('complete_download_order', [
            'order_type' => $orderType,
            'transaction_id' => $transaction->getId(),
            'num_segments' => $transaction->getNumSegments(),
        ]);

        $result = $this->createDownloadOrderResult($transaction, $order->getParserFormat());
        $order->afterExecute($result);

        return $result;
    }

    /**
     * @inheritDoc
     *
     * The method automatically:
     * - Validates the order data against XML schema
     * - Splits large data into segments (CHUNK_SIZE)
     * - Computes digest for data integrity
     * - Encrypts the order data with the transaction key
     * - Uploads all segments sequentially
     *
     * @throws EbicsException If request creation, upload, or encryption fails
     * @throws EbicsResponseException If the bank returns an error response
     */
    public function executeUploadOrder(UploadOrderInterface $order): UploadOrderResult
    {
        $order->useRequestFactory($this->requestFactory);
        $order->useOrderDataHandler($this->orderDataHandler);
        $order->useUserSignatureHandler($this->userSignatureHandler);
        $order->prepareContext();

        $orderType = $order->getOrderType();
        $this->logger->info('start_upload_order', [
            'order_type' => $orderType,
            'host_id' => $this->bank->getHostId(),
            'partner_id' => $this->user->getPartnerId(),
            'user_id' => $this->user->getUserId(),
        ]);

        $transaction = $this->uploadTransaction(
            function (UploadTransaction $transaction) use ($order) {
                $order->setTransaction($transaction);
                $orderData = $order->getOrderData();
                $orderContent = $orderData->getTrimmedContent();
                $this->schemaValidator->validate($orderData);

                $chunks = $orderData->getChunks();
                $transaction->setOrderData($chunks);
                $transaction->setNumSegments($orderData->getNumChunks());
                $transaction->setDigest($this->cryptService->hash($orderContent));

                return $order->createRequest();
            }
        );

        $this->logger->info('complete_upload_order', [
            'order_type' => $orderType,
            'transaction_id' => $transaction->getInitialization()->getTransactionId(),
            'num_segments' => $transaction->getNumSegments(),
        ]);

        $result = $this->createUploadOrderResult($transaction, $order->getOrderData());
        $order->afterExecute($result);

        return $result;
    }

    /**
     * @inheritDoc
     *
     * @throws EbicsException If signature generation fails
     * @throws PasswordEbicsException If keyring password is invalid
     */
    public function createUserSignatures(?array $options = null): void
    {
        $this->logger->info('create_user_signatures', [
            'signature_a_version' => $options['a_version'] ?? SignatureInterface::A_VERSION6,
            'host_id' => $this->bank->getHostId(),
            'partner_id' => $this->user->getPartnerId(),
            'user_id' => $this->user->getUserId(),
        ]);

        $signatureA = $this->createUserSignature(SignatureInterface::TYPE_A, $options['a_details'] ?? null);
        $this->keyring->setUserSignatureAVersion($options['a_version'] ?? SignatureInterface::A_VERSION6);
        $this->keyring->setUserSignatureA($signatureA);

        $signatureE = $this->createUserSignature(SignatureInterface::TYPE_E, $options['e_details'] ?? null);
        $this->keyring->setUserSignatureE($signatureE);

        $signatureX = $this->createUserSignature(SignatureInterface::TYPE_X, $options['x_details'] ?? null);
        $this->keyring->setUserSignatureX($signatureX);

        $this->logger->info('user_signatures_created', [
            'host_id' => $this->bank->getHostId(),
            'partner_id' => $this->user->getPartnerId(),
            'user_id' => $this->user->getUserId(),
        ]);
    }

    /**
     * @inheritDoc
     *
     * @throws EbicsException If certificate generation fails
     */
    public function generateIssuerCertificate(): array
    {
        $keyPair = $this->cryptService->generateKeyPair($this->keyring->getPassword());

        $x509Generator = $this->keyring->getCertificateGenerator();

        if ($x509Generator) {
            $certificate = $this->signatureFactory->createIssuerCertificate($x509Generator, $keyPair);
        }

        return [
            'publickey' => $keyPair->getPublicKey()->getKey(),
            'publickey_type' => $keyPair->getPublicKey()->getType(),
            'privatekey' => $keyPair->getPrivateKey()->getKey(),
            'privatekey_type' => $keyPair->getPrivateKey()->getType(),
            'certificate' => $certificate ?? null,
        ];
    }

    /**
     * Send receipt acknowledgment for a download/upload transaction.
     *
     * EBICS Protocol Context:
     * The receipt (acknowledgment) phase is the final step in the EBICS download/upload
     * transaction model. After successfully retrieving or uploading data, the client
     * must send a receipt to the bank to confirm the transaction completion.
     *
     * The receipt contains:
     * - Transaction ID: Identifies the transaction being acknowledged
     * - Acknowledged flag: true = success, false = failure/rollback
     *
     * When acknowledged=true, the bank marks the transaction as completed.
     * When acknowledged=false, the bank may allow redownloading or require action.
     *
     * For download orders, the receipt is sent after data decryption and validation.
     * For upload orders, the receipt confirms successful segment transfer.
     *
     * @param DownloadTransaction $transaction The transaction to acknowledge
     * @param bool $acknowledged True for success, false for failure/rollback
     *
     * @return void
     *
     * @throws EbicsException If receipt creation fails
     * @throws EbicsResponseException If bank returns an error response
     */
    private function transferReceipt(DownloadTransaction $transaction, bool $acknowledged): void
    {
        $this->logger->debug('send_transfer_receipt', [
            'transaction_id' => $transaction->getId(),
            'acknowledged' => $acknowledged,
        ]);

        $request = $this->requestFactory->createTransferReceipt($transaction->getId(), $acknowledged);
        $response = $this->httpClient->post($this->bank->getUrl(), $request);

        $this->verifyResponseAuthSignature($response);
        $this->checkH00XReturnCode($request, $response);

        $transaction->setReceipt($response);

        $this->logger->debug('transfer_receipt_sent', [
            'transaction_id' => $transaction->getId(),
        ]);
    }

    /**
     * Upload transaction segments to the bank during the transfer phase.
     *
     * EBICS Protocol Context:
     * The transfer phase of an upload transaction sends all order data segments
     * to the bank after the initialization phase. Each segment is:
     *
     * 1. Encrypted with the transaction key received during initialization
     * 2. Assigned a sequential segment number
     * 3. Marked as last segment or intermediate segment
     * 4. Sent to the bank via HTTP POST
     * 5. Acknowledged by the bank with a response code
     *
     * The bank processes segments sequentially and only considers the upload
     * complete when all segments (including the last segment marker) are received.
     *
     * Large files are automatically chunked into segments of UploadTransaction::CHUNK_SIZE
     * to comply with EBICS protocol size limitations.
     *
     * @param UploadTransaction $uploadTransaction The upload transaction with segments to transfer
     *
     * @return void
     *
     * @throws EbicsException If segment creation or upload fails
     * @throws EbicsResponseException If bank returns an error response
     */
    private function transferTransfer(UploadTransaction $uploadTransaction): void
    {
        $segmentCount = 0;
        foreach ($uploadTransaction->getSegments() as $segment) {
            $segmentCount++;
            $this->logger->debug('upload_transfer_segment', [
                'transaction_id' => $segment->getTransactionId(),
                'segment_number' => $segment->getSegmentNumber(),
                'is_last_segment' => $segment->isLastSegment(),
            ]);

            $request = $this->requestFactory->createTransferUpload(
                $segment->getTransactionId(),
                $segment->getTransactionKey(),
                $segment->getOrderData(),
                $segment->getSegmentNumber(),
                $segment->isLastSegment()
            );
            $response = $this->httpClient->post($this->bank->getUrl(), $request);
            $this->verifyResponseAuthSignature($response);
            $this->checkH00XReturnCode($request, $response);

            $segment->setResponse($response);
        }

        $this->logger->info('transfer_segments_uploaded', [
            'transaction_id' => $uploadTransaction->getInitialization()->getTransactionId(),
            'segment_count' => $segmentCount,
        ]);
    }

    /**
     * Validate the EBICS response return code and throw exception on error.
     *
     * EBICS Protocol Context:
     * EBICS responses use standardized return codes (H00X namespace) to indicate
     * transaction status. This method checks for:
     *
     * - '000000': Success - order executed successfully
     * - '011000': Transaction Done - download/upload completed
     * - '011001': Download Postprocess Skipped - data available but postponed
     *
     * Any other code indicates an error and throws an EbicsResponseException
     * with the appropriate error message from the bank's report text.
     *
     * Common error codes:
     * - 010000: Authentication failed
     * - 010001: Signature verification failed
     * - 061009: Invalid order data
     * - 091001: Invalid host ID
     *
     * @param Request $request The original request for error context
     * @param Response $response The bank's response containing return code
     *
     * @return void
     *
     * @throws EbicsResponseException If return code indicates an error
     */
    private function checkH00XReturnCode(Request $request, Response $response): void
    {
        $errorCode = $this->responseHandler->retrieveH00XBodyOrHeaderReturnCode($response);

        if ('000000' === $errorCode) {
            return;
        }

        // For Transaction Done.
        if ('011000' === $errorCode) {
            return;
        }

        // For Download Postprocess Skipped (postponed).
        if ('011001' === $errorCode) {
            return;
        }

        $reportText = $this->responseHandler->retrieveH00XReportText($response);

        $this->logger->error('ebics_response_error', [
            'error_code' => $errorCode,
            'report_text' => $reportText,
            'url' => $this->bank->getUrl(),
        ]);

        EbicsExceptionFactory::buildExceptionFromCode($errorCode, $reportText, $request, $response);
    }

    /**
     * Verify the bank authentication signature (X002) of a response.
     *
     * Every secured response is verified after the bank keys are received via
     * HPB. The HPB response itself is exempt because it delivers the bank keys
     * and cannot be verified against them. A failed verification aborts the
     * transaction with a SignatureEbicsException.
     *
     * @param Response $response The bank's response to verify
     *
     * @return void
     *
     * @throws SignatureEbicsException If the signature is invalid
     */
    private function verifyResponseAuthSignature(Response $response): void
    {
        try {
            $this->responseHandler->verifyAuthSignature($response, $this->keyring);
        } catch (SignatureEbicsException $exception) {
            $this->logger->error('ebics_response_auth_signature_invalid', [
                'error' => $exception->getMessage(),
                'url' => $this->bank->getUrl(),
            ]);

            throw $exception;
        }

        $this->logger->debug('bank_auth_signature_verified', [
            'url' => $this->bank->getUrl(),
        ]);
    }


    /**
     * Initialize an EBICS transaction by sending the request and receiving the response.
     *
     * EBICS Protocol Context:
     * The initialization phase is the first step in download/upload transactions.
     * The client sends the order request with:
     * - Order type (FDL, FUL, BTD, BTU)
     * - Date range (for downloads)
     * - Order parameters
     * - User signature for authentication
     *
     * The bank responds with:
     * - Transaction ID for subsequent phases
     * - Return code indicating success/failure
     * - For uploads: Transaction key for encryption
     *
     * @param callable $requestClosure Closure that creates the XML request
     * @param bool $verifyBankSignature Whether the response bank authentication
     *   signature must be verified
     *
     * @return InitializationTransaction The initialized transaction object
     *
     * @throws EbicsException If request creation fails
     * @throws EbicsResponseException If bank returns an error response
     */
    private function initializeTransaction(
        callable $requestClosure,
        bool $verifyBankSignature = true
    ): InitializationTransaction {
        $this->logger->debug('create_initialization_transaction');

        $transaction = $this->transactionFactory->createInitializationTransaction();

        $request = call_user_func($requestClosure);

        $segment = $this->retrieveInitializationSegment($request, $verifyBankSignature);
        $transaction->setInitializationSegment($segment);

        $this->logger->info('initialization_transaction_completed');

        return $transaction;
    }

    /**
     * Send initialization request and retrieve the initialization segment from the bank.
     *
     * EBICS Protocol Context:
     * Sends the order request to the bank's EBICS endpoint and processes
     * the response to extract the initialization segment. The segment contains:
     *
     * - Transaction ID: Unique identifier for the multi-phase transaction
     * - Return code: Transaction status (success/failure)
     * - Order data: Any data returned by the bank (e.g., for HPB orders)
     * - Max segment size: For subsequent download/upload phases
     *
     * For initialization orders (INI, HIA, HPB, H3K), this is the only segment
     * as these are single-phase transactions.
     *
     * @param Request $request The XML request to send
     * @param bool $verifyBankSignature Whether the response bank authentication
     *   signature must be verified
     *
     * @return InitializationSegment The response segment with transaction details
     *
     * @throws EbicsException If HTTP request fails
     * @throws EbicsResponseException If bank returns an error response
     */
    private function retrieveInitializationSegment(
        Request $request,
        bool $verifyBankSignature = true
    ): InitializationSegment {
        $this->logger->debug('send_initialization_request', [
            'url' => $this->bank->getUrl(),
        ]);

        $response = $this->httpClient->post($this->bank->getUrl(), $request);

        if ($verifyBankSignature) {
            $this->verifyResponseAuthSignature($response);
        }
        $this->checkH00XReturnCode($request, $response);

        $this->logger->debug('initialization_segment_received', [
            'url' => $this->bank->getUrl(),
        ]);

        return $this->responseHandler->extractInitializationSegment($response, $this->keyring);
    }

    /**
     * Execute a multi-phase download transaction.
     *
     * EBICS Protocol Context:
     * This method orchestrates the complete download process following the
     * EBICS download transaction model:
     *
     * 1. Initialization Phase:
     *    - Create download request with order type and date range
     *    - Send request to bank
     *    - Receive transaction ID and max segment size
     *
     * 2. Retrieval Phase:
     *    - Loop through all segments until last segment is reached
     *    - Request each segment using transaction ID and segment number
     *    - Reassemble segments into complete order data
     *
     * 3. Decryption Phase:
     *    - Base64 decode the order data
     *    - Decrypt using transaction key from the bank
     *    - Decompress ZIP-encoded data
     *
     * 4. Receipt Phase:
     *    - Call custom acknowledgment closure if provided
     *    - Send receipt confirmation to bank (default: acknowledged=true)
     *
     * The method handles automatic segment management, buffering large data
     * to prevent memory issues with large file downloads.
     *
     * @param callable $requestClosure Closure that creates the XML request
     * @param callable|null $ackClosure Optional closure to customize receipt acknowledgment
     *   Receives DownloadTransaction and returns bool for acknowledged status
     *
     * @return DownloadTransaction The completed transaction with order data
     *
     * @throws EbicsException If download, decryption, or receipt fails
     * @throws EbicsResponseException If bank returns an error response
     */
    private function downloadTransaction(callable $requestClosure, ?callable $ackClosure = null): DownloadTransaction
    {
        $this->logger->debug('init_download_transaction', [
            'url' => $this->bank->getUrl(),
        ]);

        $transaction = $this->transactionFactory->createDownloadTransaction();

        $segmentNumber = null;
        $isLastSegment = null;

        $request = call_user_func_array($requestClosure, [$segmentNumber, $isLastSegment]);

        $segment = $this->retrieveDownloadSegment($request);
        $transaction->addSegment($segment);

        $lastSegment = $transaction->getLastSegment();

        while (!$lastSegment->isLastSegmentNumber()) {
            $nextSegmentNumber = $lastSegment->getNextSegmentNumber();
            $isLastNextSegmentNumber = $lastSegment->isLastNextSegmentNumber();

            $request = $this->requestFactory->createTransferDownload(
                $lastSegment->getTransactionId(),
                $nextSegmentNumber,
                $isLastNextSegmentNumber
            );

            $segment = $this->retrieveDownloadSegment($request);
            $transaction->addSegment($segment);

            $segment->setNumSegments($lastSegment->getNumSegments());
            $segment->setTransactionKey($lastSegment->getTransactionKey());

            $lastSegment = $segment;
        }

        $this->logger->info('download_segments_retrieved', [
            'transaction_id' => $lastSegment->getTransactionId(),
            'num_segments' => $lastSegment->getNumSegments(),
        ]);

        $segments = [];
        foreach ($transaction->getSegments() as $segment) {
            $segments[] = $segment->getOrderData();
            $segment->setOrderData('');
        }

        $orderDataEncoded = implode('', $segments);

        $orderDataDecoded = $this->base64Encoder->decode($orderDataEncoded);
        $orderDataCompressed = $this->aesEncryptor->decrypt($orderDataDecoded, [
            'keyring' => $this->keyring,
            'transactionKey' => $lastSegment->getTransactionKey(),
        ]);
        $transaction->setOrderData($this->zipCompressor->uncompress($orderDataCompressed));

        $this->logger->debug('download_data_decrypted', [
            'transaction_id' => $lastSegment->getTransactionId(),
        ]);

        if (null !== $ackClosure) {
            $acknowledged = call_user_func_array($ackClosure, [$transaction]);
        } else {
            $acknowledged = true;
        }

        $this->transferReceipt($transaction, $acknowledged);

        return $transaction;
    }

    /**
     * Retrieve a download segment from the bank.
     *
     * EBICS Protocol Context:
     * Requests a specific segment of the downloadable data from the bank.
     * Each segment response contains:
     *
     * - Transaction ID: For subsequent segment requests
     * - Segment number: Current segment position
     * - Last segment flag: Whether more segments follow
     * - Total segments: Total number of segments (when known)
     * - Order data: The actual segment data (base64 encoded, encrypted)
     * - Transaction key: For decrypting the order data (in first segment)
     *
     * @param Request $request The segment request with transaction ID and segment number
     *
     * @return DownloadSegment The retrieved segment with data
     *
     * @throws EbicsException If HTTP request fails
     * @throws EbicsResponseException If bank returns an error response
     */
    private function retrieveDownloadSegment(Request $request): DownloadSegment
    {
        $this->logger->debug('download_segment', [
            'url' => $this->bank->getUrl(),
        ]);

        $response = $this->httpClient->post($this->bank->getUrl(), $request);

        $this->verifyResponseAuthSignature($response);
        $this->checkH00XReturnCode($request, $response);

        return $this->responseHandler->extractDownloadSegment($response);
    }

    /**
     * Execute a multi-phase upload transaction.
     *
     * EBICS Protocol Context:
     * This method orchestrates the complete upload process following the
     * EBICS upload transaction model:
     *
     * 1. Initialization Phase:
     *    - Create upload request with order type and metadata
     *    - Send request to bank
     *    - Receive transaction ID and transaction key for encryption
     *
     * 2. Transfer Phase (if data exists):
     *    - Split order data into segments (CHUNK_SIZE)
     *    - Encrypt each segment with transaction key
     *    - Upload each segment sequentially
     *    - Receive acknowledgment for each segment
     *
     * 3. Receipt Phase:
     *    - Bank processes all segments
     *    - Returns final transaction status
     *
     * The method handles:
     * - Order data validation against XML schema
     * - Automatic segmentation of large data
     * - Digest computation for data integrity
     * - Transaction key management for encryption
     *
     * @param callable $requestClosure Closure that creates the XML request
     *   Receives UploadTransaction and returns Request
     *
     * @return UploadTransaction The completed transaction with upload status
     *
     * @throws EbicsException If upload or encryption fails
     * @throws EbicsResponseException If bank returns an error response
     */
    private function uploadTransaction(callable $requestClosure): UploadTransaction
    {
        $this->logger->debug('init_upload_transaction', [
            'url' => $this->bank->getUrl(),
        ]);

        $transaction = $this->transactionFactory->createUploadTransaction();
        $transaction->setKey($this->cryptService->generateTransactionKey());

        $request = call_user_func_array($requestClosure, [$transaction]);

        $response = $this->httpClient->post($this->bank->getUrl(), $request);
        $this->verifyResponseAuthSignature($response);
        $this->checkH00XReturnCode($request, $response);

        $uploadSegment = $this->responseHandler->extractUploadSegment($request, $response);
        $transaction->setInitialization($uploadSegment);

        $this->logger->info('upload_transaction_initialized', [
            'transaction_id' => $transaction->getInitialization()->getTransactionId(),
            'num_segments' => $transaction->getNumSegments(),
        ]);

        if ($transaction->getNumSegments() > 0) {
            foreach ($transaction->getOrderData() as $orderDataChunkId => $orderDataChunk) {
                $segment = $this->segmentFactory->createTransferSegment();
                $segment->setTransactionKey($transaction->getKey());
                $segment->setSegmentNumber($orderDataChunkId + 1);
                $segment->setLastSegment($segment->getSegmentNumber() === $transaction->getNumSegments());
                $segment->setOrderData($orderDataChunk);

                $segment->setNumSegments($transaction->getNumSegments());
                $segment->setTransactionId($transaction->getInitialization()->getTransactionId());

                if ($segment->getTransactionId()) {
                    $transaction->addSegment($segment);
                }
            }

            $this->transferTransfer($transaction);
        }

        return $transaction;
    }

    private function createStandardOrderResult(Response $response): StandardOrderResult
    {
        $orderResult = $this->orderResultFactory->createStandardOrderResult();
        $orderResult->setResponse($response);

        return $orderResult;
    }

    private function createInitializationOrderResult(InitializationTransaction $transaction): InitializationOrderResult
    {
        $orderResult = $this->orderResultFactory->createInitializationOrderResult();
        $orderResult->setTransaction($transaction);
        $orderResult->setData($transaction->getOrderData());
        $orderResult->setDocument($this->documentFactory->createXml($orderResult->getData()));

        return $orderResult;
    }

    private function createDownloadOrderResult(
        DownloadTransaction $transaction,
        string $parserFormat
    ): DownloadOrderResult {
        $orderResult = $this->orderResultFactory->createDownloadOrderResult();
        $orderResult->setTransaction($transaction);
        $orderResult->setData($transaction->getOrderData());

        switch ($parserFormat) {
            case self::FILE_PARSER_FORMAT_TEXT:
                break;
            case self::FILE_PARSER_FORMAT_XML:
                $orderResult->setDocument($this->documentFactory->createXml($orderResult->getData()));
                break;
            case self::FILE_PARSER_FORMAT_XML_FILES:
                $files = $this->xmlService->extractFilesFromString($orderResult->getData());
                $orderResult->setDataFiles($this->documentFactory->createMultipleXml($files));
                break;
            case self::FILE_PARSER_FORMAT_ZIP_FILES:
                $zipFiles = $this->zipArchiveExtractor->extractFilesFromString($orderResult->getData());
                $orderResult->setDataFiles(array_filter($zipFiles, fn($v) => $v !== false));
                break;
            default:
                throw new LogicException('Incorrect format');
        }

        return $orderResult;
    }

    private function createUploadOrderResult(
        UploadTransaction $transaction,
        OrderDataInterface $document
    ): UploadOrderResult {
        $orderResult = $this->orderResultFactory->createUploadOrderResult();
        $orderResult->setTransaction($transaction);
        $orderResult->setDataDocument($document);
        $orderResult->setData($document->getContent());

        return $orderResult;
    }

    /**
     * @inheritDoc
     */
    public function getKeyring(): Keyring
    {
        return $this->keyring;
    }

    /**
     * @inheritDoc
     */
    public function getBank(): Bank
    {
        return $this->bank;
    }

    /**
     * @inheritDoc
     */
    public function getUser(): User
    {
        return $this->user;
    }

    /**
     * Create new signature.
     *
     * @param string $type
     * @param array<string, mixed>|null $details
     * @return SignatureInterface
     * @throws PasswordEbicsException
     */
    private function createUserSignature(string $type, ?array $details = null): SignatureInterface
    {
        switch ($type) {
            case SignatureInterface::TYPE_A:
                if (null !== $details) {
                    $keyPair = new KeyPair(
                        new Key($details['publickey'], $details['publickey_type']),
                        new Key($details['privatekey'], $details['privatekey_type']),
                        $this->keyring->getPassword()
                    );
                    if (isset($details['certificate'])) {
                        $certificateGenerator = new ContentX509Generator();
                        $certificateGenerator->setAContent($details['certificate']);
                    } else {
                        $certificateGenerator = null;
                    }
                } else {
                    $keyPair = $this->cryptService->generateKeyPair($this->keyring->getPassword());
                    $certificateGenerator = $this->keyring->getCertificateGenerator();
                }

                $signature = $this->signatureFactory->createSignatureAFromKeys(
                    $keyPair,
                    $certificateGenerator
                );
                break;
            case SignatureInterface::TYPE_E:
                $keyPair = $this->cryptService->generateKeyPair($this->keyring->getPassword());
                $signature = $this->signatureFactory->createSignatureEFromKeys(
                    $keyPair,
                    $this->keyring->getCertificateGenerator()
                );
                break;
            case SignatureInterface::TYPE_X:
                $keyPair = $this->cryptService->generateKeyPair($this->keyring->getPassword());
                $signature = $this->signatureFactory->createSignatureXFromKeys(
                    $keyPair,
                    $this->keyring->getCertificateGenerator()
                );
                break;
            default:
                throw new LogicException(sprintf('Type "%s" not allowed', $type));
        }

        return $signature;
    }

    /**
     * @inheritDoc
     */
    public function getResponseHandler(): ResponseHandler
    {
        return $this->responseHandler;
    }

    /**
     * Get the PSR-3 logger instance.
     *
     * @return LoggerInterface The logger instance
     */
    public function getLogger(): LoggerInterface
    {
        return $this->logger;
    }

    /**
     * @inheritDoc
     * @throws PasswordEbicsException
     */
    public function checkKeyring(): bool
    {
        return $this->cryptService->checkPrivateKey(
            $this->keyring->getUserSignatureX()->getPrivateKey(),
            $this->keyring->getPassword()
        );
    }

    /**
     * @inheritDoc
     * @throws PasswordEbicsException
     */
    public function changeKeyringPassword(string $newPassword): void
    {
        $keyPair = $this->cryptService->changePrivateKeyPassword(
            new KeyPair(
                $this->keyring->getUserSignatureA()->getPublicKey(),
                $this->keyring->getUserSignatureA()->getPrivateKey(),
                $this->keyring->getPassword()
            ),
            $this->keyring->getPassword(),
            $newPassword
        );

        $signature = $this->signatureFactory->createSignatureAFromKeys(
            $keyPair,
            $this->keyring->getCertificateGenerator()
        );

        $this->keyring->setUserSignatureA($signature);

        $keyPair = $this->cryptService->changePrivateKeyPassword(
            new KeyPair(
                $this->keyring->getUserSignatureX()->getPublicKey(),
                $this->keyring->getUserSignatureX()->getPrivateKey(),
                $this->keyring->getPassword()
            ),
            $this->keyring->getPassword(),
            $newPassword
        );

        $signature = $this->signatureFactory->createSignatureXFromKeys(
            $keyPair,
            $this->keyring->getCertificateGenerator()
        );

        $this->keyring->setUserSignatureX($signature);

        $keyPair = $this->cryptService->changePrivateKeyPassword(
            new KeyPair(
                $this->keyring->getUserSignatureE()->getPublicKey(),
                $this->keyring->getUserSignatureE()->getPrivateKey(),
                $this->keyring->getPassword()
            ),
            $this->keyring->getPassword(),
            $newPassword
        );

        $signature = $this->signatureFactory->createSignatureEFromKeys(
            $keyPair,
            $this->keyring->getCertificateGenerator()
        );

        $this->keyring->setUserSignatureE($signature);

        $this->keyring->setPassword($newPassword);
    }
}
