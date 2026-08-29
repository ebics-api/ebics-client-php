<?php

namespace EbicsApi\Ebics\Services;

use EbicsApi\Ebics\Contracts\HttpClientInterface;
use EbicsApi\Ebics\Models\Http\Request;
use EbicsApi\Ebics\Models\Http\Response;
use LogicException;

/**
 * Fake HTTP client that returns fixture-based responses for testing.
 *
 * This client simulates bank server responses using pre-defined XML fixture
 * files stored in a fixtures directory. Instead of making real HTTP calls,
 * it parses the EBICS request to determine the order type (e.g., INI, HIA, FDL)
 * and returns the corresponding fixture file as the response.
 *
 * This is essential for unit testing EBICS client code without requiring
 * actual bank server access, enabling fast and reliable test execution.
 *
 * Fixture file naming conventions:
 * - Standard orders: `{order_type}.xml` (e.g., `ini.xml`, `hia.xml`)
 * - Extended orders (FUL, FDL, BTU, BTD): `{order_type}.{file_format}.xml`
 *   (e.g., `ful.camt.053.xml`, `fdl.swift.mt940.xml`)
 * - Transaction phases: `receipt.xml`, `transfer.xml`
 * - HEV requests: `hev.xml`
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class FakerHttpClient implements HttpClientInterface
{
    /**
     * Order types that use extended fixture naming (order_type.file_format.xml).
     *
     * @var array<int, string>
     */
    private array $extendedOrderTypes;

    /**
     * Constructor.
     *
     * @param string $fixturesDir Path to directory containing XML fixture files
     * @param array<int, string>|null $extendedOrderTypes Order types using extended naming.
     *                                                     Default: ['FUL', 'FDL', 'BTU', 'BTD']
     */
    public function __construct(
        private readonly string $fixturesDir,
        ?array $extendedOrderTypes = null
    ) {
        $this->extendedOrderTypes = $extendedOrderTypes ?? ['FUL', 'FDL', 'BTU', 'BTD'];
    }

    /**
     * Return a fixture-based response based on the request content.
     *
     * Parses the XML request to determine the order type or transaction phase,
     * then loads and returns the corresponding fixture file.
     *
     * @param string $url Ignored (not used for fixture lookup)
     * @param Request $request The EBICS XML request to parse for fixture matching
     *
     * @return Response The fixture response, or empty Response if no fixture matches
     * @throws LogicException If a matched fixture file doesn't exist or transaction phase is unsupported
     */
    public function post(string $url, Request $request): Response
    {
        $requestContent = $request->getContent();

        $orderTypeMatches = [];
        $orderTypeMatch = preg_match(
            '/(<OrderType>|<AdminOrderType>)(?<order_type>.*?)(<\/OrderType>|<\/AdminOrderType>)/',
            $requestContent,
            $orderTypeMatches
        );

        if ($orderTypeMatch) {
            $fileFormatMatches = [];
            preg_match(
                '/<FileFormat.*>(?<file_format>.*)<\/FileFormat>/',
                $requestContent,
                $fileFormatMatches
            );

            $btfOrderParamsMatches = [];
            preg_match(
                '/<ServiceName.*>(?<service_name>.*)<\/ServiceName>.*?<MsgName.*>(?<msg_name>.*)<\/MsgName>/',
                $requestContent,
                $btfOrderParamsMatches
            );

            $svcOrderParamsMatches = [];
            preg_match(
                '/<OrderType.*>(?<order_type>.*)<\/OrderType>/',
                $requestContent,
                $svcOrderParamsMatches
            );

            $fileName = $this->fixtureFileName(
                $orderTypeMatches['order_type'],
                [
                    'file_format' => $fileFormatMatches['file_format'] ??
                        (
                        (!empty($btfOrderParamsMatches['service_name']) && !empty($btfOrderParamsMatches['msg_name'])) ?
                            $btfOrderParamsMatches['service_name'] . '.' . $btfOrderParamsMatches['msg_name']
                            : ($svcOrderParamsMatches['order_type'] ?? null)
                        ),
                ]
            );

            return $this->readFixture($fileName);
        }

        $transactionPhaseMatches = [];
        $transactionPhaseMatch = preg_match(
            '/<TransactionPhase>(?<transaction_phase>.*)<\/TransactionPhase>/',
            $requestContent,
            $transactionPhaseMatches
        );

        if ($transactionPhaseMatch) {
            return $this->fixtureTransactionPhase($transactionPhaseMatches['transaction_phase']);
        }

        $hevRequestMatch = preg_match(
            '/<ebicsHEVRequest .*>/',
            $requestContent
        );

        if ($hevRequestMatch) {
            return $this->readFixture('hev.xml');
        }

        return new Response();
    }

    /**
     * Determine the fixture file name based on order type and options.
     *
     * For extended order types (FUL, FDL, BTU, BTD), the naming includes
     * the file format: `{order_type}.{file_format}.xml`.
     * For standard orders, the naming is simply: `{order_type}.xml`.
     *
     * @param string $orderType The EBICS order type (e.g., 'INI', 'HIA', 'FUL')
     * @param array<string, string|null>|null $options Additional options for fixture lookup:
     *                                                 ['file_format' => '<string>']
     *
     * @return string The fixture file name (lowercase, e.g., 'ini.xml', 'ful.camt.053.xml')
     */
    protected function fixtureFileName(string $orderType, ?array $options = null): string
    {
        if (in_array($orderType, $this->extendedOrderTypes)) {
            $fileFormat = $options['file_format'] ?? '';
            $fileName = sprintf(strtolower($orderType) . '.%s.xml', strtolower($fileFormat));
        } else {
            $fileName = strtolower($orderType) . '.xml';
        }

        return $fileName;
    }

    /**
     * Return a fixture response for a specific transaction phase.
     *
     * Supported phases: 'Receipt', 'Transfer'
     *
     * @param string $transactionPhase The transaction phase name (case-sensitive)
     *
     * @return Response The fixture response for the transaction phase
     * @throws LogicException If the transaction phase is not supported
     */
    private function fixtureTransactionPhase(string $transactionPhase): Response
    {
        switch ($transactionPhase) {
            case 'Receipt':
            case 'Transfer':
                $fileName = strtolower($transactionPhase) . '.xml';
                break;
            default:
                throw new LogicException(sprintf('Faked transaction phase `%s` not supported.', $transactionPhase));
        }

        return $this->readFixture($fileName);
    }

    private function readFixture(string $fileName): Response
    {
        $fixturePath = $this->fixturesDir . '/' . $fileName;

        if (!is_file($fixturePath)) {
            throw new LogicException(sprintf('Fixtures file %s does not exists.', $fileName));
        }

        $response = new Response();

        $responseContent = file_get_contents($fixturePath);

        if (!is_string($responseContent)) {
            throw new LogicException('Response content is not valid.');
        }

        // Compact XML to canonical form (same as EbicsResponseBuilder::sign()):
        // Collapse whitespace between tags to nothing.
        // Note: we do NOT trim text node values because C14N includes
        // text node whitespace in canonical form, and signatures cover
        // the compact-on-wire form, not a normalized form.
        $responseContent = preg_replace('/[\r\n]/u', '', $responseContent);
        $responseContent = preg_replace('#>\s+<#', '><', $responseContent);

        if (!is_string($responseContent)) {
            throw new LogicException('Response content is not valid.');
        }

        $response->loadXML($responseContent);

        return $response;
    }
}
