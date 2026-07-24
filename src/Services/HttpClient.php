<?php

namespace EbicsApi\Ebics\Services;

use EbicsApi\Ebics\Contracts\HttpClientInterface;
use EbicsApi\Ebics\Models\Http\Response;
use RuntimeException;

/**
 * Base HTTP client for EBICS protocol communication.
 *
 * Abstract base class providing common functionality for concrete HTTP client
 * implementations. All HTTP clients in this library send EBICS XML requests
 * to bank servers and parse the XML responses.
 *
 * Concrete implementations:
 * - `CurlHttpClient`: Uses PHP cURL extension (default)
 * - `PsrHttpClient`: Uses PSR-18 HTTP client interface for framework integration
 * - `FakerHttpClient`: Returns fixture-based responses for testing
 * - `DebuggerHttpClient`: Throws exceptions with request data for debugging
 *
 * The Content-Type for all requests is `text/xml; charset=UTF-8` as required
 * by the EBICS protocol specification.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
abstract class HttpClient implements HttpClientInterface
{
    /**
     * EBICS protocol requires this Content-Type for all HTTP requests.
     */
    protected const CONTENT_TYPE = 'text/xml; charset=UTF-8';

    /**
     * Parse an XML response string and create a Response object.
     *
     * @param string $contents The raw XML response from the bank server
     *
     * @return Response Parsed XML response object
     * @throws RuntimeException If the response content is empty
     */
    protected function createResponse(string $contents): Response
    {
        if (empty($contents)) {
            throw new RuntimeException('Response is empty.');
        }

        $response = new Response();

        $previous = libxml_use_internal_errors(true);
        libxml_clear_errors();

        $loaded = $response->loadXML($contents, LIBXML_NONET | LIBXML_NOENT);

        if (false === $loaded) {
            $errors = libxml_get_errors();
            libxml_clear_errors();
            libxml_use_internal_errors($previous);

            $message = 'Failed to load XML response.';
            if ([] !== $errors) {
                $details = implode(
                    '; ',
                    array_map(
                        static fn($error) => trim($error->message),
                        $errors
                    )
                );
                $message .= ' ' . $details;
            }

            throw new RuntimeException($message);
        }

        libxml_use_internal_errors($previous);

        return $response;
    }
}
