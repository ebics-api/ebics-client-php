<?php

namespace EbicsApi\Ebics\Contexts;

use DateTime;
use DateTimeInterface;
use EbicsApi\Ebics\Contracts\OrderContextInterface;
use EbicsApi\Ebics\Contracts\SignatureDataInterface;
use EbicsApi\Ebics\Models\Bank;
use EbicsApi\Ebics\Models\Keyring;
use EbicsApi\Ebics\Models\User;

/**
 * EBICS Request Context - Container for EBICS request parameters and transaction state.
 *
 * EBICS Protocol Context:
 * The RequestContext holds all parameters required to build an EBICS XML request and
 * manage the transaction state throughout the request-response lifecycle. It serves
 * as a data container that flows through the order creation and execution process.
 *
 * Key Components:
 *
 * Identity & Security:
 * - bank: EBICS server identification (Host ID, URL, country)
 * - user: Subscriber identification (Partner ID, User ID)
 * - keyring: Cryptographic material (signatures, certificates, keys)
 * - withES: Whether electronic signature is required for the order
 *
 * Transaction State:
 * - transactionId: Unique identifier for multi-phase transactions
 * - transactionKey: AES key for encrypting order data (from bank)
 * - segmentNumber/isLastSegment: For segmented downloads/uploads
 * - numSegments: Total number of segments to transfer
 *
 * Date Ranges:
 * - startDateTime/endDateTime: For download orders with date filtering
 * - dateTime: Current timestamp for request signing
 *
 * Order Data:
 * - orderType: EBICS order code (INI, HIA, FDL, FUL, etc.)
 * - orderData: XML payload for upload orders
 * - dataDigest: Hash of order data for integrity verification
 *
 * Product Information:
 * - product: Client product name sent in requests
 * - language: Language preference for bank responses
 *
 * Advanced:
 * - ackClosure: Custom closure to control receipt acknowledgment
 * - orderContext: Order-specific parameters (FDL, FUL, BTD, BTU contexts)
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class RequestContext
{
    /**
     * Request have both ES and OrderData
     */
    private bool $withES;

    /**
     * @var callable|null $ackClosure Custom closure to handle download acknowledge. Return boolean.
     */
    private $ackClosure = null;

    private string $orderType;
    private Bank $bank;
    private User $user;
    private Keyring $keyring;
    private DateTimeInterface $dateTime;
    private ?DateTimeInterface $startDateTime;
    private ?DateTimeInterface $endDateTime;
    private string $receiptCode;
    private ?int $segmentNumber;
    private ?bool $isLastSegment;
    private string $transactionId;
    private string $transactionKey;
    private int $numSegments;
    private string $orderData;
    private SignatureDataInterface $signatureData;
    private string $dataDigest;
    private string $signatureVersion;
    private readonly string $product;
    private string $language;
    private ?OrderContextInterface $orderContext = null;

    public function __construct()
    {
        $this->dateTime = new DateTime();
        $this->withES = false;
        $this->product = 'Ebics client PHP';
        $this->language = 'en';
    }

    public function setBank(Bank $bank): RequestContext
    {
        $this->bank = $bank;

        return $this;
    }

    public function getBank(): Bank
    {
        return $this->bank;
    }

    public function setUser(User $user): RequestContext
    {
        $this->user = $user;

        return $this;
    }

    public function getUser(): User
    {
        return $this->user;
    }

    public function setKeyring(Keyring $keyring): RequestContext
    {
        $this->keyring = $keyring;

        return $this;
    }

    public function getKeyring(): Keyring
    {
        return $this->keyring;
    }

    public function setDateTime(DateTimeInterface $dateTime): RequestContext
    {
        $this->dateTime = $dateTime;

        return $this;
    }

    public function getDateTime(): DateTimeInterface
    {
        return $this->dateTime;
    }

    public function setStartDateTime(?DateTimeInterface $startDateTime): RequestContext
    {
        $this->startDateTime = $startDateTime;

        return $this;
    }

    public function getStartDateTime(): ?DateTimeInterface
    {
        return $this->startDateTime;
    }

    public function setEndDateTime(?DateTimeInterface $endDateTime): RequestContext
    {
        $this->endDateTime = $endDateTime;

        return $this;
    }

    public function getEndDateTime(): ?DateTimeInterface
    {
        return $this->endDateTime;
    }

    public function setWithES(bool $withES): RequestContext
    {
        $this->withES = $withES;

        return $this;
    }

    public function isWithES(): bool
    {
        return $this->withES;
    }

    public function setReceiptCode(string $receiptCode): RequestContext
    {
        $this->receiptCode = $receiptCode;

        return $this;
    }

    public function getReceiptCode(): string
    {
        return $this->receiptCode;
    }

    public function setSegmentNumber(?int $segmentNumber): RequestContext
    {
        $this->segmentNumber = $segmentNumber;

        return $this;
    }

    public function getSegmentNumber(): ?int
    {
        return $this->segmentNumber;
    }

    public function setLastSegment(?bool $lastSegment): RequestContext
    {
        $this->isLastSegment = $lastSegment;

        return $this;
    }

    public function isLastSegment(): ?bool
    {
        return $this->isLastSegment;
    }

    public function setTransactionId(string $transactionId): RequestContext
    {
        $this->transactionId = $transactionId;

        return $this;
    }

    public function getTransactionId(): string
    {
        return $this->transactionId;
    }

    public function setTransactionKey(string $transactionKey): RequestContext
    {
        $this->transactionKey = $transactionKey;

        return $this;
    }

    public function getTransactionKey(): string
    {
        return $this->transactionKey;
    }

    public function setNumSegments(int $numSegments): RequestContext
    {
        $this->numSegments = $numSegments;

        return $this;
    }

    public function getNumSegments(): int
    {
        return $this->numSegments;
    }

    public function setOrderData(string $orderData): RequestContext
    {
        $this->orderData = $orderData;

        return $this;
    }

    public function getOrderData(): string
    {
        return $this->orderData;
    }

    public function setSignatureData(SignatureDataInterface $signatureData): RequestContext
    {
        $this->signatureData = $signatureData;

        return $this;
    }

    public function getSignatureData(): SignatureDataInterface
    {
        return $this->signatureData;
    }

    public function setDataDigest(?string $dataDigest): RequestContext
    {
        $this->dataDigest = $dataDigest;

        return $this;
    }

    public function getDataDigest(): string
    {
        return $this->dataDigest;
    }

    public function setSignatureVersion(string $signatureVersion): RequestContext
    {
        $this->signatureVersion = $signatureVersion;

        return $this;
    }

    public function getSignatureVersion(): string
    {
        return $this->signatureVersion;
    }

    public function getAckClosure(): ?callable
    {
        return $this->ackClosure;
    }

    public function setAckClosure(?callable $ackClosure): RequestContext
    {
        $this->ackClosure = $ackClosure;

        return $this;
    }

    public function getProduct(): string
    {
        return $this->product;
    }

    public function setLanguage(string $language): RequestContext
    {
        $this->language = $language;

        return $this;
    }

    public function getLanguage(): string
    {
        return $this->language;
    }

    public function getOrderType(): string
    {
        return $this->orderType;
    }

    public function setOrderType(string $orderType): RequestContext
    {
        $this->orderType = $orderType;

        return $this;
    }

    public function getOrderContext(): ?OrderContextInterface
    {
        return $this->orderContext;
    }

    public function setOrderContext(?OrderContextInterface $orderContext): RequestContext
    {
        $this->orderContext = $orderContext;

        return $this;
    }
}
