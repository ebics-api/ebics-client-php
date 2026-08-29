<?php

namespace EbicsApi\Ebics\Contracts;

use DOMDocument;
use EbicsApi\Ebics\Exceptions\EbicsException;
use EbicsApi\Ebics\Exceptions\SignatureEbicsException;
use EbicsApi\Ebics\Models\DownloadSegment;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Http\Response;
use EbicsApi\Ebics\Models\InitializationSegment;
use EbicsApi\Ebics\Models\Keyring;
use EbicsApi\Ebics\Models\UploadSegment;

/**
 * Response Handler interface.
 *
 * Parses and extracts data from EBICS bank server responses.
 * Handles response validation, segment extraction, and error detection.
 *
 * EBICS Protocol Context:
 * After every EBICS request, the bank returns an XML response that may
 * contain:
 * - Return codes (system and business level) indicating success/failure
 * - Transaction metadata (ID, phase, segment count)
 * - Encrypted order data (for download and initialization responses)
 * - Transaction keys for decrypting order data
 *
 * The ResponseHandler is responsible for:
 * 1. Validating return codes and throwing exceptions on errors
 * 2. Extracting transaction metadata
 * 3. Decrypting and decompressing order data
 * 4. Creating typed segment objects (InitializationSegment, DownloadSegment, UploadSegment)
 *
 * EBICS responses follow two schema versions:
 * - H000: System-level responses (e.g., HEV protocol version check)
 * - H00X: Business-level responses (all other orders)
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
interface ResponseHandlerInterface
{
    /**
     * Extract the ReturnCode from the H00X response header.
     *
     * @param DOMDocument $xml The response DOM document
     *
     * @return string The header return code (e.g., "000000" for success)
     */
    public function retrieveH00XReturnCode(DOMDocument $xml): string;

    /**
     * Extract the ReturnCode from the H00X response body.
     *
     * @param DOMDocument $xml The response DOM document
     *
     * @return string The body return code
     */
    public function retrieveH00XBodyReturnCode(DOMDocument $xml): string;

    /**
     * Extract the ReportText from the H00X response header.
     *
     * @param DOMDocument $xml The response DOM document
     *
     * @return string The human-readable report text
     */
    public function retrieveH00XReportText(DOMDocument $xml): string;

    /**
     * Extract the TransactionID from the H00X response.
     *
     * The transaction ID is assigned by the bank for multi-phase
     * transactions (download/upload).
     *
     * @param DOMDocument $xml The response DOM document
     *
     * @return string|null The transaction ID, or null if not present
     */
    public function retrieveH00XTransactionId(DOMDocument $xml): ?string;

    /**
     * Extract the TransactionPhase from the H00X response.
     *
     * Indicates the current phase of a multi-phase transaction
     * (e.g., "Initialisation", "Transfer", "Receipt").
     *
     * @param DOMDocument $xml The response DOM document
     *
     * @return string|null The transaction phase, or null if not present
     */
    public function retrieveH00XTransactionPhase(DOMDocument $xml): ?string;

    /**
     * Extract the NumSegments from the H00X response.
     *
     * @param DOMDocument $xml The response DOM document
     *
     * @return string|null The total number of segments, or null if not present
     */
    public function retrieveH00XNumSegments(DOMDocument $xml): ?string;

    /**
     * Extract the OrderID from the request data.
     *
     * @param DOMDocument $xml The response DOM document
     *
     * @return string The order ID from the request
     */
    public function retrieveH00XRequestOrderId(DOMDocument $xml): string;

    /**
     * Extract the OrderID from the response header.
     *
     * @param DOMDocument $xml The response DOM document
     *
     * @return string The order ID from the response
     */
    public function retrieveH00XResponseOrderId(DOMDocument $xml): string;

    /**
     * Extract the SegmentNumber from the H00X response.
     *
     * @param DOMDocument $xml The response DOM document
     *
     * @return string|null The current segment number, or null if not present
     */
    public function retrieveH00XSegmentNumber(DOMDocument $xml): ?string;

    /**
     * Extract the encrypted TransactionKey from the H00X response.
     *
     * The transaction key is used to decrypt the order data.
     *
     * @param DOMDocument $xml The response DOM document
     *
     * @return string|null The base64-encoded transaction key, or null if not present
     */
    public function retrieveH00XTransactionKey(DOMDocument $xml): ?string;

    /**
     * Extract the encrypted OrderData from the H00X response.
     *
     * @param DOMDocument $xml The response DOM document
     *
     * @return string|null The base64-encoded encrypted order data, or null if not present
     */
    public function retrieveH00XOrderData(DOMDocument $xml): ?string;

    /**
     * Extract the ReturnCode from both H00X header and body.
     *
     * Checks the header first; if it's "000000", falls back to the body
     * return code. This handles edge cases where some banks return
     * different codes in header vs body.
     *
     * @param DOMDocument $xml The response DOM document
     *
     * @return string The combined return code
     */
    public function retrieveH00XBodyOrHeaderReturnCode(DOMDocument $xml): string;

    /**
     * Extract the ReturnCode from an H000 (system-level) response.
     *
     * H000 responses are used for system-level operations like
     * protocol version checks (HEV order).
     *
     * @param DOMDocument $xml The response DOM document
     *
     * @return string The system return code
     */
    public function retrieveH000ReturnCode(DOMDocument $xml): string;

    /**
     * Extract the ReportText from an H000 (system-level) response.
     *
     * @param DOMDocument $xml The response DOM document
     *
     * @return string The system report text
     */
    public function retrieveH000ReportText(DOMDocument $xml): string;

    /**
     * Extract and decrypt an InitializationSegment from the response.
     *
     * Decrypts the order data using the transaction key and keyring,
     * then decompresses the result to produce the initialization segment.
     * Used for INI, HIA, H3K, and HPB order responses.
     *
     * @param Response $response The HTTP response from the bank
     * @param Keyring $keyring The keyring containing decryption keys
     *
     * @return InitializationSegment The decrypted and decompressed initialization segment
     *
     * @throws EbicsException If decryption or extraction fails
     */
    public function extractInitializationSegment(Response $response, Keyring $keyring): InitializationSegment;

    /**
     * Extract a DownloadSegment from the response.
     *
     * Parses transaction metadata and encrypted order data from a
     * download response. The order data remains encrypted at this stage.
     *
     * @param Response $response The HTTP response from the bank
     *
     * @return DownloadSegment The download segment with encrypted order data
     */
    public function extractDownloadSegment(Response $response): DownloadSegment;

    /**
     * Extract an UploadSegment from the request and response.
     *
     * @param Request $request The original upload request sent to the bank
     * @param Response $response The HTTP response from the bank
     *
     * @return UploadSegment The upload segment with transaction metadata
     */
    public function extractUploadSegment(Request $request, Response $response): UploadSegment;

    /**
     * Validate the response return codes and throw exceptions on errors.
     *
     * Checks the appropriate return code (H000 or H00X) based on the
     * response type. Accepts success codes (000000, 011000, 011001)
     * and throws an EbicsException for any other code.
     *
     * @param Request $request The original request for error context
     * @param Response $response The response to validate
     *
     * @return void
     *
     * @throws EbicsException If the response indicates an error
     */
    public function checkResponseReturnCode(Request $request, Response $response): void;

    /**
     * Verify the bank authentication signature (X002) of the response.
     *
     * The verification follows the EBICS authentication signature scheme:
     * 1. The ds:DigestValue must match the SHA-256 hash of the canonicalized
     *    (C14N) nodes marked with authenticate="true".
     * 2. The ds:SignatureValue must be a valid RSASSA-PKCS1-v1_5 with SHA-256
     *    signature (made by the bank X002 private key) over the canonicalized
     *    ds:SignedInfo element.
     *
     * Verification is skipped for responses without an AuthSignature element
     * (HEV and unsecured INI/HIA/H3K responses).
     *
     * @param Response $response The response to verify
     * @param Keyring $keyring The keyring containing the bank X002 public key
     *
     * @return void
     *
     * @throws SignatureEbicsException If the digest or the signature is invalid,
     *   or if the bank X002 key is not available in the keyring
     */
    public function verifyAuthSignature(Response $response, Keyring $keyring): void;
}
